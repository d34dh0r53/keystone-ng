// Test the LDAP backend implementation

use openstack_keystone::config::Config;
use openstack_keystone::identity::backends::ldap::LdapBackend;
use openstack_keystone::identity::backends::IdentityBackend;
use openstack_keystone::identity::types::{
    GroupListParameters, UserListParameters, UserPasswordAuthRequest,
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration
    let config_path = PathBuf::from("tools/keystone-ldap.conf");
    let config = Config::new(config_path)?;

    println!("✓ Configuration loaded successfully");
    println!("  LDAP URL: {}", config.ldap.url);
    println!("  User tree DN: {}", config.ldap.user_tree_dn);
    println!("  Group tree DN: {}", config.ldap.group_tree_dn);
    println!();

    // Create LDAP backend
    let mut backend = LdapBackend::default();
    backend.set_config(config.clone());

    println!("✓ LDAP backend initialized");
    println!();

    // Create a minimal ServiceState (for now we'll use dummy values since we're testing the backend directly)
    // In a real scenario, this would come from the running service
    
    println!("=== Testing User Operations ===");
    println!();

    // Test 1: List all users
    println!("1. Listing all users:");
    let users = openstack_keystone::identity::backends::ldap::user::list(
        &config.ldap,
        &UserListParameters::default(),
        "default",
    )
    .await?;
    
    println!("   Found {} users:", users.len());
    for user in &users {
        println!("   - {} (ID: {}, Domain: {}, Enabled: {})", 
            user.name, user.id, user.domain_id, user.enabled);
    }
    println!();

    // Test 2: Get specific user
    println!("2. Getting user 'alice':");
    let alice = openstack_keystone::identity::backends::ldap::user::get(
        &config.ldap,
        "alice",
        "default",
    )
    .await?;
    
    if let Some(user) = alice {
        println!("   ✓ Found: {} (Domain: {}, Enabled: {})",
            user.name, user.domain_id, user.enabled);
    } else {
        println!("   ✗ User not found");
    }
    println!();

    // Test 3: Authenticate user
    println!("3. Authenticating user 'alice':");
    let auth_request = UserPasswordAuthRequest {
        id: Some("alice".to_string()),
        name: None,
        domain: None,
        password: "password123".to_string(),
    };
    
    match openstack_keystone::identity::backends::ldap::authenticate::authenticate_by_password(
        &config.ldap,
        &auth_request,
        "default",
    )
    .await
    {
        Ok(auth_info) => {
            println!("   ✓ Authentication successful");
            println!("     User ID: {}", auth_info.user_id);
            println!("     Methods: {:?}", auth_info.methods);
        }
        Err(e) => {
            println!("   ✗ Authentication failed: {}", e);
        }
    }
    println!();

    println!("=== Testing Group Operations ===");
    println!();

    // Test 4: List all groups
    println!("4. Listing all groups:");
    let groups = openstack_keystone::identity::backends::ldap::group::list(
        &config.ldap,
        &GroupListParameters::default(),
        "default",
    )
    .await?;
    
    println!("   Found {} groups:", groups.len());
    for group in &groups {
        println!("   - {} (ID: {}, Domain: {})", 
            group.name, group.id, group.domain_id);
        if let Some(desc) = &group.description {
            println!("     Description: {}", desc);
        }
    }
    println!();

    // Test 5: Get specific group
    println!("5. Getting group 'developers':");
    let developers = openstack_keystone::identity::backends::ldap::group::get(
        &config.ldap,
        "developers",
        "default",
    )
    .await?;
    
    if let Some(group) = developers {
        println!("   ✓ Found: {} (Domain: {})",
            group.name, group.domain_id);
        if let Some(desc) = &group.description {
            println!("     Description: {}", desc);
        }
    } else {
        println!("   ✗ Group not found");
    }
    println!();

    // Test 6: List groups for a user
    println!("6. Listing groups for user 'alice':");
    let alice_groups = openstack_keystone::identity::backends::ldap::user_group::list_user_groups(
        &config.ldap,
        "alice",
        "default",
    )
    .await?;
    
    println!("   User 'alice' is member of {} groups:", alice_groups.len());
    for group in &alice_groups {
        println!("   - {}", group.name);
    }
    println!();

    // Test 7: List groups for another user
    println!("7. Listing groups for user 'bob':");
    let bob_groups = openstack_keystone::identity::backends::ldap::user_group::list_user_groups(
        &config.ldap,
        "bob",
        "default",
    )
    .await?;
    
    println!("   User 'bob' is member of {} groups:", bob_groups.len());
    for group in &bob_groups {
        println!("   - {}", group.name);
    }
    println!();

    println!("=== All Tests Completed Successfully! ===");

    Ok(())
}
