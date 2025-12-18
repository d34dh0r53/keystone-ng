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
use openstack_keystone::identity::backends::ldap::user;
use openstack_keystone::identity::types::UserListParameters;

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_list_users() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let params = UserListParameters::default();

    let result = user::list(&config, &params, DEFAULT_DOMAIN).await;
    assert!(result.is_ok(), "Failed to list users: {:?}", result.err());

    let users = result.unwrap();
    assert!(!users.is_empty(), "Expected at least one user");

    // Check that test users exist
    let user_names: Vec<_> = users.iter().map(|u| u.name.as_str()).collect();
    assert!(
        user_names.contains(&"alice") || user_names.contains(&"bob"),
        "Expected test users not found. Users: {:?}",
        user_names
    );
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_list_users_with_filter() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let params = UserListParameters {
        name: Some("alice".to_string()),
        ..Default::default()
    };

    let result = user::list(&config, &params, DEFAULT_DOMAIN).await;
    assert!(result.is_ok(), "Failed to list users: {:?}", result.err());

    let users = result.unwrap();
    assert_eq!(users.len(), 1, "Expected exactly one user named 'alice'");
    assert_eq!(users[0].name, "alice");
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_get_user() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();

    let result = user::get(&config, "alice", DEFAULT_DOMAIN).await;
    assert!(result.is_ok(), "Failed to get user: {:?}", result.err());

    let user = result.unwrap();
    assert!(user.is_some(), "User 'alice' not found");

    let user = user.unwrap();
    assert_eq!(user.id, "alice");
    assert_eq!(user.name, "alice");
    assert_eq!(user.domain_id, DEFAULT_DOMAIN);
    assert!(user.enabled, "User should be enabled");
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_get_nonexistent_user() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();

    let result = user::get(&config, "nonexistent_user_12345", DEFAULT_DOMAIN).await;
    assert!(result.is_ok(), "Should return Ok with None for nonexistent user");

    let user = result.unwrap();
    assert!(user.is_none(), "Expected None for nonexistent user");
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389 with write permissions"]
async fn test_create_and_delete_user() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let test_user_id = "test_user_temp";
    let test_user_name = "test_user_temp";

    // Clean up any existing user from failed tests
    let _ = user::delete(&config, test_user_id).await;

    // Create user
    let create_result = user::create(&config, test_user_id, test_user_name, DEFAULT_DOMAIN).await;
    
    if !config.allow_create {
        assert!(
            create_result.is_err(),
            "Create should fail when allow_create is false"
        );
        return;
    }

    assert!(
        create_result.is_ok(),
        "Failed to create user: {:?}",
        create_result.err()
    );

    let created_user = create_result.unwrap();
    assert_eq!(created_user.id, test_user_id);
    assert_eq!(created_user.name, test_user_name);

    // Verify user exists
    let get_result = user::get(&config, test_user_id, DEFAULT_DOMAIN).await;
    assert!(get_result.is_ok());
    assert!(get_result.unwrap().is_some());

    // Delete user
    let delete_result = user::delete(&config, test_user_id).await;
    assert!(
        delete_result.is_ok(),
        "Failed to delete user: {:?}",
        delete_result.err()
    );

    // Verify user no longer exists
    let get_after_delete = user::get(&config, test_user_id, DEFAULT_DOMAIN).await;
    assert!(get_after_delete.is_ok());
    assert!(get_after_delete.unwrap().is_none());
}
