// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! LDAP user-group membership operations.

use ldap3::{Mod, Scope, SearchEntry};

use crate::config::LdapConfig;
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::types::Group;

use super::connection::{connect, escape_filter_chars};
use super::mapping::{build_group_dn, build_user_dn, entry_to_group, get_group_members};

/// List groups a user is a member of.
pub async fn list_user_groups(
    config: &LdapConfig,
    user_id: &str,
    domain_id: &str,
) -> Result<Vec<Group>, IdentityDatabaseError> {
    let mut ldap = connect(config).await?;

    let user_dn = build_user_dn(user_id, config);
    let escaped_dn = escape_filter_chars(&user_dn);

    // Search for groups where the user is a member
    let filter = format!(
        "(&(objectClass={})({

}={}))",
        config.group_objectclass, config.group_member_attribute, escaped_dn
    );

    let (rs, _res) = ldap
        .search(&config.group_tree_dn, Scope::Subtree, &filter, vec!["*"])
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let mut groups = Vec::new();
    for entry in rs {
        let search_entry = SearchEntry::construct(entry);
        match entry_to_group(search_entry, config, domain_id) {
            Ok(group) => groups.push(group),
            Err(e) => {
                tracing::warn!("Failed to convert LDAP entry to group: {}", e);
            }
        }
    }

    let _ = ldap.unbind().await;
    Ok(groups)
}

/// Add a user to a group.
pub async fn add_user_to_group(
    config: &LdapConfig,
    user_id: &str,
    group_id: &str,
) -> Result<(), IdentityDatabaseError> {
    if !config.allow_update {
        return Err(IdentityDatabaseError::LdapReadOnly);
    }

    let mut ldap = connect(config).await?;

    let user_dn = build_user_dn(user_id, config);
    let group_dn = build_group_dn(group_id, config);

    // Add user DN to group's member attribute
    let mods = vec![Mod::Add(
        config.group_member_attribute.clone(),
        vec![user_dn].into_iter().collect(),
    )];

    ldap.modify(&group_dn, mods)
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let _ = ldap.unbind().await;
    Ok(())
}

/// Remove a user from a group.
pub async fn remove_user_from_group(
    config: &LdapConfig,
    user_id: &str,
    group_id: &str,
) -> Result<(), IdentityDatabaseError> {
    if !config.allow_update {
        return Err(IdentityDatabaseError::LdapReadOnly);
    }

    let mut ldap = connect(config).await?;

    let user_dn = build_user_dn(user_id, config);
    let group_dn = build_group_dn(group_id, config);

    // Remove user DN from group's member attribute
    let mods = vec![Mod::Delete(
        config.group_member_attribute.clone(),
        vec![user_dn].into_iter().collect(),
    )];

    ldap.modify(&group_dn, mods)
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let _ = ldap.unbind().await;
    Ok(())
}
