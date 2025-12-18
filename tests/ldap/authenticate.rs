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

use super::common::*;
use openstack_keystone::identity::backends::ldap::authenticate;
use openstack_keystone::identity::types::UserPasswordAuthRequest;

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_authenticate_by_password_success() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let auth_request = UserPasswordAuthRequest {
        id: Some("alice".to_string()),
        name: None,
        domain: None,
        password: "password123".to_string(),
    };

    let result = authenticate::authenticate_by_password(&config, &auth_request, DEFAULT_DOMAIN).await;
    assert!(
        result.is_ok(),
        "Authentication should succeed: {:?}",
        result.err()
    );

    let auth_info = result.unwrap();
    assert_eq!(auth_info.user_id, "alice");
    assert!(auth_info.methods.contains(&"password".to_string()));
    assert!(auth_info.user.is_some(), "User details should be populated");

    let user = auth_info.user.unwrap();
    assert_eq!(user.name, "alice");
    assert_eq!(user.domain_id, DEFAULT_DOMAIN);
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_authenticate_by_name_success() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let auth_request = UserPasswordAuthRequest {
        id: None,
        name: Some("bob".to_string()),
        domain: None,
        password: "password123".to_string(),
    };

    let result = authenticate::authenticate_by_password(&config, &auth_request, DEFAULT_DOMAIN).await;
    assert!(
        result.is_ok(),
        "Authentication by name should succeed: {:?}",
        result.err()
    );

    let auth_info = result.unwrap();
    assert_eq!(auth_info.user_id, "bob");
    assert!(auth_info.user.is_some());
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_authenticate_wrong_password() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let auth_request = UserPasswordAuthRequest {
        id: Some("alice".to_string()),
        name: None,
        domain: None,
        password: "wrong_password".to_string(),
    };

    let result = authenticate::authenticate_by_password(&config, &auth_request, DEFAULT_DOMAIN).await;
    assert!(
        result.is_err(),
        "Authentication should fail with wrong password"
    );
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_authenticate_nonexistent_user() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let auth_request = UserPasswordAuthRequest {
        id: Some("nonexistent_user".to_string()),
        name: None,
        domain: None,
        password: "any_password".to_string(),
    };

    let result = authenticate::authenticate_by_password(&config, &auth_request, DEFAULT_DOMAIN).await;
    assert!(
        result.is_err(),
        "Authentication should fail for nonexistent user"
    );
}
