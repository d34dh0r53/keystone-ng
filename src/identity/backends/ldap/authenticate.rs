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

//! LDAP authentication via bind.

use crate::auth::AuthenticatedInfo;
use crate::config::LdapConfig;
use crate::identity::backends::error::IdentityDatabaseError;
use crate::identity::types::UserPasswordAuthRequest;

use super::connection::authenticate_bind;
use super::mapping::build_user_dn;
use super::user;

/// Authenticate user by password via LDAP bind.
pub async fn authenticate_by_password(
    config: &LdapConfig,
    auth: &UserPasswordAuthRequest,
    domain_id: &str,
) -> Result<AuthenticatedInfo, IdentityDatabaseError> {
    // Get user ID from auth request
    let user_id = if let Some(id) = &auth.id {
        id.clone()
    } else if let Some(name) = &auth.name {
        // If only name provided, search for user first
        let users = user::list(
            config,
            &crate::identity::types::UserListParameters {
                name: Some(name.clone()),
                ..Default::default()
            },
            domain_id,
        )
        .await?;

        users
            .first()
            .ok_or_else(|| IdentityDatabaseError::UserNotFound(name.clone()))?
            .id
            .clone()
    } else {
        return Err(IdentityDatabaseError::UserIdOrNameWithDomain);
    };

    // Build user DN
    let user_dn = build_user_dn(&user_id, config);

    // Attempt to bind with user credentials
    let password: &str = &auth.password;

    let authenticated = authenticate_bind(config, &user_dn, password).await?;

    if !authenticated {
        return Err(IdentityDatabaseError::LdapBindFailed(format!(
            "Authentication failed for user: {}",
            user_id
        )));
    }

    // Fetch user details
    let user = user::get(config, &user_id, domain_id)
        .await?
        .ok_or_else(|| IdentityDatabaseError::UserNotFound(user_id.clone()))?;

    Ok(AuthenticatedInfo {
        user_id: user.id.clone(),
        user: Some(user),
        methods: vec!["password".to_string()],
        ..Default::default()
    })
}
