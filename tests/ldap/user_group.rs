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
use openstack_keystone::identity::backends::ldap::user_group;

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_list_user_groups_alice() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();

    let result = user_group::list_user_groups(&config, "alice", DEFAULT_DOMAIN).await;
    assert!(
        result.is_ok(),
        "Failed to list groups for alice: {:?}",
        result.err()
    );

    let groups = result.unwrap();
    assert!(!groups.is_empty(), "Alice should be a member of at least one group");

    let group_names: Vec<_> = groups.iter().map(|g| g.name.as_str()).collect();
    
    // Alice should be in admins and users groups (based on test-data.ldif)
    assert!(
        group_names.contains(&"admins"),
        "Alice should be in 'admins' group. Found: {:?}",
        group_names
    );
    assert!(
        group_names.contains(&"users"),
        "Alice should be in 'users' group. Found: {:?}",
        group_names
    );
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_list_user_groups_bob() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();

    let result = user_group::list_user_groups(&config, "bob", DEFAULT_DOMAIN).await;
    assert!(
        result.is_ok(),
        "Failed to list groups for bob: {:?}",
        result.err()
    );

    let groups = result.unwrap();
    assert!(!groups.is_empty(), "Bob should be a member of at least one group");

    let group_names: Vec<_> = groups.iter().map(|g| g.name.as_str()).collect();
    
    // Bob should be in developers and users groups (based on test-data.ldif)
    assert!(
        group_names.contains(&"developers"),
        "Bob should be in 'developers' group. Found: {:?}",
        group_names
    );
    assert!(
        group_names.contains(&"users"),
        "Bob should be in 'users' group. Found: {:?}",
        group_names
    );
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_list_user_groups_nonexistent() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();

    let result = user_group::list_user_groups(&config, "nonexistent_user", DEFAULT_DOMAIN).await;
    assert!(result.is_ok(), "Should return Ok for nonexistent user");

    let groups = result.unwrap();
    assert!(
        groups.is_empty(),
        "Nonexistent user should not be in any groups"
    );
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389 with write permissions"]
async fn test_add_and_remove_user_from_group() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let user_id = "charlie";
    let group_id = "admins";

    // First, check if charlie is already in admins
    let groups_before = user_group::list_user_groups(&config, user_id, DEFAULT_DOMAIN)
        .await
        .unwrap();
    let was_member = groups_before.iter().any(|g| g.id == group_id);

    if was_member {
        // If already a member, remove first
        let _ = user_group::remove_user_from_group(&config, user_id, group_id).await;
    }

    // Add user to group
    let add_result = user_group::add_user_to_group(&config, user_id, group_id).await;

    if !config.allow_update {
        assert!(
            add_result.is_err(),
            "Add should fail when allow_update is false"
        );
        return;
    }

    assert!(
        add_result.is_ok(),
        "Failed to add user to group: {:?}",
        add_result.err()
    );

    // Verify user is in group
    let groups_after_add = user_group::list_user_groups(&config, user_id, DEFAULT_DOMAIN)
        .await
        .unwrap();
    assert!(
        groups_after_add.iter().any(|g| g.id == group_id),
        "User should be in group after add"
    );

    // Remove user from group
    let remove_result = user_group::remove_user_from_group(&config, user_id, group_id).await;
    assert!(
        remove_result.is_ok(),
        "Failed to remove user from group: {:?}",
        remove_result.err()
    );

    // Verify user is no longer in group
    let groups_after_remove = user_group::list_user_groups(&config, user_id, DEFAULT_DOMAIN)
        .await
        .unwrap();
    assert!(
        !groups_after_remove.iter().any(|g| g.id == group_id),
        "User should not be in group after remove"
    );

    // Restore original state if user was a member
    if was_member {
        let _ = user_group::add_user_to_group(&config, user_id, group_id).await;
    }
}
