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

use openstack_keystone::config::{Config, LdapConfig};
use std::path::PathBuf;

/// Get LDAP test configuration
pub fn get_ldap_config() -> LdapConfig {
    // Try to load from config file first
    if let Ok(config) = Config::new(PathBuf::from("tools/keystone-ldap.conf")) {
        return config.ldap;
    }

    // Fallback to default test configuration
    LdapConfig {
        url: "ldap://localhost:1389".to_string(),
        user: Some("cn=admin,dc=example,dc=org".to_string()),
        password: Some("admin".into()),
        suffix: "dc=example,dc=org".to_string(),
        user_tree_dn: "ou=Users,dc=example,dc=org".to_string(),
        user_objectclass: "inetOrgPerson".to_string(),
        user_id_attribute: "cn".to_string(),
        user_name_attribute: "cn".to_string(),
        user_mail_attribute: "mail".to_string(),
        user_enabled_default: true,
        group_tree_dn: "ou=Groups,dc=example,dc=org".to_string(),
        group_objectclass: "groupOfNames".to_string(),
        group_id_attribute: "cn".to_string(),
        group_name_attribute: "cn".to_string(),
        group_desc_attribute: "description".to_string(),
        group_member_attribute: "member".to_string(),
        allow_create: true,
        allow_update: true,
        allow_delete: true,
        ..Default::default()
    }
}

/// Default domain ID for LDAP tests
pub const DEFAULT_DOMAIN: &str = "default";

/// Check if LDAP server is available
pub async fn ldap_available() -> bool {
    let config = get_ldap_config();
    openstack_keystone::identity::backends::ldap::user::list(
        &config,
        &openstack_keystone::identity::types::UserListParameters::default(),
        DEFAULT_DOMAIN,
    )
    .await
    .is_ok()
}
