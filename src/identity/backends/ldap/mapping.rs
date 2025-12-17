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

//! LDAP attribute mapping between LDAP entries and Keystone data models.

use ldap3::SearchEntry;
use std::collections::HashSet;

use crate::config::LdapConfig;
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::types::{Group, UserResponse, UserResponseBuilder};

/// Extract a single string attribute from an LDAP entry.
pub fn get_string_attr(
    entry: &SearchEntry,
    attr_name: &str,
) -> Result<String, IdentityDatabaseError> {
    entry
        .attrs
        .get(attr_name)
        .and_then(|v| v.first())
        .map(|s| s.clone())
        .ok_or_else(|| {
            IdentityDatabaseError::LdapAttributeMapping(format!(
                "Missing required attribute: {}",
                attr_name
            ))
        })
}

/// Extract an optional string attribute from an LDAP entry.
pub fn get_optional_string_attr(entry: &SearchEntry, attr_name: &str) -> Option<String> {
    entry
        .attrs
        .get(attr_name)
        .and_then(|v| v.first())
        .map(|s| s.clone())
}

/// Extract multiple string values from an LDAP attribute.
pub fn get_multi_string_attr(entry: &SearchEntry, attr_name: &str) -> Vec<String> {
    entry
        .attrs
        .get(attr_name)
        .map(|v| v.clone())
        .unwrap_or_default()
}

/// Check if user is enabled based on LDAP attribute.
pub fn is_user_enabled(entry: &SearchEntry, config: &LdapConfig) -> bool {
    if let Some(attr_name) = &config.user_enabled_attribute {
        if let Some(value) = get_optional_string_attr(entry, attr_name) {
            // If mask is configured, check bitmask
            if let Some(mask) = config.user_enabled_mask {
                if let Ok(num_value) = value.parse::<u32>() {
                    return (num_value & mask) != 0;
                }
            }
            // Otherwise check boolean-ish values
            return matches!(
                value.to_lowercase().as_str(),
                "true" | "yes" | "1" | "enabled" | "active"
            );
        }
    }
    // Default if attribute not present
    config.user_enabled_default
}

/// Convert LDAP search entry to Keystone UserResponse.
pub fn entry_to_user(
    entry: SearchEntry,
    config: &LdapConfig,
    domain_id: &str,
) -> Result<UserResponse, IdentityDatabaseError> {
    let id = get_string_attr(&entry, &config.user_id_attribute)?;
    let name = get_string_attr(&entry, &config.user_name_attribute)?;
    let enabled = is_user_enabled(&entry, config);
    // Note: email is not part of standard UserResponse, stored in extra if needed

    UserResponseBuilder::default()
        .id(id)
        .name(name)
        .domain_id(domain_id.to_string())
        .enabled(enabled)
        .build()
        .map_err(|e| {
            IdentityDatabaseError::LdapAttributeMapping(format!("Failed to build user: {}", e))
        })
}

/// Convert LDAP search entry to Keystone Group.
pub fn entry_to_group(
    entry: SearchEntry,
    config: &LdapConfig,
    domain_id: &str,
) -> Result<Group, IdentityDatabaseError> {
    let id = get_string_attr(&entry, &config.group_id_attribute)?;
    let name = get_string_attr(&entry, &config.group_name_attribute)?;
    let description = get_optional_string_attr(&entry, &config.group_desc_attribute);

    Ok(Group {
        id,
        name,
        domain_id: domain_id.to_string(),
        description,
        ..Default::default()
    })
}

/// Extract group member DNs from a group entry.
pub fn get_group_members(entry: &SearchEntry, config: &LdapConfig) -> HashSet<String> {
    get_multi_string_attr(entry, &config.group_member_attribute)
        .into_iter()
        .collect()
}

/// Build user DN from user ID and configuration.
pub fn build_user_dn(user_id: &str, config: &LdapConfig) -> String {
    format!("{}={},{}", config.user_id_attribute, user_id, config.user_tree_dn)
}

/// Build group DN from group ID and configuration.
pub fn build_group_dn(group_id: &str, config: &LdapConfig) -> String {
    format!("{}={},{}", config.group_id_attribute, group_id, config.group_tree_dn)
}

/// Extract ID from DN (get the first RDN value).
pub fn extract_id_from_dn(dn: &str) -> Option<String> {
    dn.split(',')
        .next()
        .and_then(|rdn| rdn.split('=').nth(1))
        .map(|s| s.to_string())
}
