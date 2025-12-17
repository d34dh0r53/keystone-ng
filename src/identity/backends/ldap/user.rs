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

//! LDAP user operations.

use ldap3::{Scope, SearchEntry};

use crate::config::LdapConfig;
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::types::{UserListParameters, UserResponse};

use super::connection::{build_filter, connect, escape_filter_chars};
use super::mapping::{build_user_dn, entry_to_user};

/// List users from LDAP.
pub async fn list(
    config: &LdapConfig,
    params: &UserListParameters,
    domain_id: &str,
) -> Result<Vec<UserResponse>, IdentityDatabaseError> {
    let mut ldap = connect(config).await?;

    // Build search filter
    let mut filter = format!("(objectClass={})", config.user_objectclass);
    
    // Add name filter if provided
    if let Some(name) = &params.name {
        let escaped_name = escape_filter_chars(name);
        filter = format!(
            "(&{}({}={}))",
            filter, config.user_name_attribute, escaped_name
        );
    }

    filter = build_filter(&filter, config.user_filter.as_ref());

    let (rs, _res) = ldap
        .search(&config.user_tree_dn, Scope::Subtree, &filter, vec!["*"])
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let mut users = Vec::new();
    for entry in rs {
        let search_entry = SearchEntry::construct(entry);
        match entry_to_user(search_entry, config, domain_id) {
            Ok(user) => users.push(user),
            Err(e) => {
                tracing::warn!("Failed to convert LDAP entry to user: {}", e);
            }
        }
    }

    let _ = ldap.unbind().await;
    Ok(users)
}

/// Get a single user by ID from LDAP.
pub async fn get(
    config: &LdapConfig,
    user_id: &str,
    domain_id: &str,
) -> Result<Option<UserResponse>, IdentityDatabaseError> {
    let mut ldap = connect(config).await?;

    let escaped_id = escape_filter_chars(user_id);
    let filter = format!(
        "(&(objectClass={})({

}={}))",
        config.user_objectclass, config.user_id_attribute, escaped_id
    );
    let filter = build_filter(&filter, config.user_filter.as_ref());

    let (rs, _res) = ldap
        .search(&config.user_tree_dn, Scope::Subtree, &filter, vec!["*"])
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let result = if let Some(entry) = rs.into_iter().next() {
        let search_entry = SearchEntry::construct(entry);
        Some(entry_to_user(search_entry, config, domain_id)?)
    } else {
        None
    };

    let _ = ldap.unbind().await;
    Ok(result)
}

/// Create a user in LDAP (if write operations are allowed).
pub async fn create(
    config: &LdapConfig,
    user_id: &str,
    name: &str,
    domain_id: &str,
) -> Result<UserResponse, IdentityDatabaseError> {
    if !config.allow_create {
        return Err(IdentityDatabaseError::LdapReadOnly);
    }

    let mut ldap = connect(config).await?;

    let dn = build_user_dn(user_id, config);
    let attrs = vec![
        ("objectClass".to_string(), vec![config.user_objectclass.clone()].into_iter().collect()),
        (config.user_id_attribute.clone(), vec![user_id.to_string()].into_iter().collect()),
        (config.user_name_attribute.clone(), vec![name.to_string()].into_iter().collect()),
    ];

    ldap.add(&dn, attrs)
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let _ = ldap.unbind().await;

    // Return the created user
    get(config, user_id, domain_id)
        .await?
        .ok_or_else(|| IdentityDatabaseError::LdapEntryNotFound(user_id.to_string()))
}

/// Delete a user from LDAP (if write operations are allowed).
pub async fn delete(
    config: &LdapConfig,
    user_id: &str,
) -> Result<(), IdentityDatabaseError> {
    if !config.allow_delete {
        return Err(IdentityDatabaseError::LdapReadOnly);
    }

    let mut ldap = connect(config).await?;

    let dn = build_user_dn(user_id, config);

    ldap.delete(&dn)
        .await
        .map_err(|e| IdentityDatabaseError::LdapSearch(e.to_string()))?
        .success()
        .map_err(|e| IdentityDatabaseError::LdapSearch(format!("{:?}", e)))?;

    let _ = ldap.unbind().await;
    Ok(())
}
