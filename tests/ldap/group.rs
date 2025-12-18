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
use openstack_keystone::identity::backends::ldap::group;
use openstack_keystone::identity::types::GroupListParameters;

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_list_groups() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let params = GroupListParameters::default();

    let result = group::list(&config, &params, DEFAULT_DOMAIN).await;
    assert!(result.is_ok(), "Failed to list groups: {:?}", result.err());

    let groups = result.unwrap();
    assert!(!groups.is_empty(), "Expected at least one group");

    // Check that test groups exist
    let group_names: Vec<_> = groups.iter().map(|g| g.name.as_str()).collect();
    assert!(
        group_names.contains(&"admins") || group_names.contains(&"developers"),
        "Expected test groups not found. Groups: {:?}",
        group_names
    );
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_list_groups_with_filter() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let params = GroupListParameters {
        name: Some("developers".to_string()),
        ..Default::default()
    };

    let result = group::list(&config, &params, DEFAULT_DOMAIN).await;
    assert!(result.is_ok(), "Failed to list groups: {:?}", result.err());

    let groups = result.unwrap();
    assert_eq!(
        groups.len(),
        1,
        "Expected exactly one group named 'developers'"
    );
    assert_eq!(groups[0].name, "developers");
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_get_group() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();

    let result = group::get(&config, "developers", DEFAULT_DOMAIN).await;
    assert!(result.is_ok(), "Failed to get group: {:?}", result.err());

    let group = result.unwrap();
    assert!(group.is_some(), "Group 'developers' not found");

    let group = group.unwrap();
    assert_eq!(group.id, "developers");
    assert_eq!(group.name, "developers");
    assert_eq!(group.domain_id, DEFAULT_DOMAIN);
    assert!(
        group.description.is_some(),
        "Group should have a description"
    );
    assert_eq!(group.description.unwrap(), "Developer group");
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389"]
async fn test_get_nonexistent_group() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();

    let result = group::get(&config, "nonexistent_group_12345", DEFAULT_DOMAIN).await;
    assert!(
        result.is_ok(),
        "Should return Ok with None for nonexistent group"
    );

    let group = result.unwrap();
    assert!(group.is_none(), "Expected None for nonexistent group");
}

#[tokio::test]
#[ignore = "requires LDAP server on localhost:1389 with write permissions"]
async fn test_create_and_delete_group() {
    if !ldap_available().await {
        eprintln!("LDAP server not available, skipping test");
        return;
    }

    let config = get_ldap_config();
    let test_group_id = "test_group_temp";
    let test_group_name = "test_group_temp";

    // Clean up any existing group from failed tests
    let _ = group::delete(&config, test_group_id).await;

    // Create group
    let create_result = group::create(&config, test_group_id, test_group_name, DEFAULT_DOMAIN).await;

    if !config.allow_create {
        assert!(
            create_result.is_err(),
            "Create should fail when allow_create is false"
        );
        return;
    }

    assert!(
        create_result.is_ok(),
        "Failed to create group: {:?}",
        create_result.err()
    );

    let created_group = create_result.unwrap();
    assert_eq!(created_group.id, test_group_id);
    assert_eq!(created_group.name, test_group_name);

    // Verify group exists
    let get_result = group::get(&config, test_group_id, DEFAULT_DOMAIN).await;
    assert!(get_result.is_ok());
    assert!(get_result.unwrap().is_some());

    // Delete group
    let delete_result = group::delete(&config, test_group_id).await;
    assert!(
        delete_result.is_ok(),
        "Failed to delete group: {:?}",
        delete_result.err()
    );

    // Verify group no longer exists
    let get_after_delete = group::get(&config, test_group_id, DEFAULT_DOMAIN).await;
    assert!(get_after_delete.is_ok());
    assert!(get_after_delete.unwrap().is_none());
}
