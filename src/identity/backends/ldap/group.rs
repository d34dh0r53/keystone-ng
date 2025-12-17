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

//! LDAP group operations.

use ldap3::{Scope, SearchEntry};

use crate::config::LdapConfig;
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::types::{Group, GroupListParameters};

use super::connection::{build_filter, connect, escape_filter_chars};
use super::mapping::{build_group_dn, entry_to_group};

/// List groups from LDAP.
pub async fn list(
    config: &LdapConfig,
    params: &GroupListParameters,
    domain_id: &str,
) -> Result<Vec<Group>, IdentityDatabaseError> {
    let mut ldap = connect(config).await?;

    let mut filter = format!("(objectClass={})", config.group_objectclass);

    if let Some(name) = &params.name {
        let escaped_name = escape_filter_chars(name);
        filter = format!(
            "(&{}({}={}))",
            filter, config.group_name_attribute, escaped_name
        );
    }

    filter = build_filter(&filter, config.group_filter.as_ref());

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

/// Get a single group by ID from LDAP.
pub async fn get(
    config: &LdapConfig,
    group_id: &str,
    domain_id: &str,
) -> Result<Option<Group>, IdentityDatabaseError> {
    let mut ldap = connect(config).await?;

    let escaped_id = escape_filter_chars(group_id);
    let filter = format!(
        "(&(objectClass={})({

}={}))",
        config.group_objectclass, config.group_id_attribute, escaped_id
    );
    let filter = build_filter(&filter, config.group_filter.as_ref());

    let (rs, _res) = ldap
        .search(&config.group_tree_dn, Scope::Subtree, &filter, vec!["*"])
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let result = if let Some(entry) = rs.into_iter().next() {
        let search_entry = SearchEntry::construct(entry);
        Some(entry_to_group(search_entry, config, domain_id)?)
    } else {
        None
    };

    let _ = ldap.unbind().await;
    Ok(result)
}

/// Create a group in LDAP (if write operations are allowed).
pub async fn create(
    config: &LdapConfig,
    group_id: &str,
    name: &str,
    domain_id: &str,
) -> Result<Group, IdentityDatabaseError> {
    if !config.allow_create {
        return Err(IdentityDatabaseError::LdapReadOnly);
    }

    let mut ldap = connect(config).await?;

    let dn = build_group_dn(group_id, config);
    let attrs = vec![
        ("objectClass".to_string(), vec![config.group_objectclass.clone()].into_iter().collect()),
        (config.group_id_attribute.clone(), vec![group_id.to_string()].into_iter().collect()),
        (config.group_name_attribute.clone(), vec![name.to_string()].into_iter().collect()),
    ];

    ldap.add(&dn, attrs)
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let _ = ldap.unbind().await;

    get(config, group_id, domain_id)
        .await?
        .ok_or_else(|| IdentityDatabaseError::LdapEntryNotFound(group_id.to_string()))
}

/// Delete a group from LDAP (if write operations are allowed).
pub async fn delete(
    config: &LdapConfig,
    group_id: &str,
) -> Result<(), IdentityDatabaseError> {
    if !config.allow_delete {
        return Err(IdentityDatabaseError::LdapReadOnly);
    }

    let mut ldap = connect(config).await?;

    let dn = build_group_dn(group_id, config);

    ldap.delete(&dn)
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let _ = ldap.unbind().await;
    Ok(())
}
