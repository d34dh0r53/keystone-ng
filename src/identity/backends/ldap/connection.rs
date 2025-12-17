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

//! LDAP connection management.

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use secrecy::ExposeSecret;
use std::time::Duration;

use crate::config::LdapConfig;
use crate::identity::backends::error::IdentityDatabaseError;

/// Establish an LDAP connection based on configuration.
pub async fn connect(config: &LdapConfig) -> Result<Ldap, IdentityDatabaseError> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(config.timeout))
        .set_starttls(config.use_tls);

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &config.url)
        .await
        .map_err(|e| IdentityDatabaseError::LdapConnection(e.to_string()))?;

    // Spawn the connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            tracing::error!("LDAP connection driver error: {}", e);
        }
    });

    // Bind with service account if configured
    if let (Some(user), Some(password)) = (&config.user, &config.password) {
        ldap.simple_bind(user, password.expose_secret())
            .await
            .map_err(|e| IdentityDatabaseError::LdapBindFailed(e.to_string()))?
            .success()
            .map_err(|e| IdentityDatabaseError::LdapBindFailed(format!("{:?}", e)))?;
    } else {
        // Anonymous bind
        ldap.simple_bind("", "")
            .await
            .map_err(|e| IdentityDatabaseError::LdapBindFailed(e.to_string()))?
            .success()
            .map_err(|e| IdentityDatabaseError::LdapBindFailed(format!("{:?}", e)))?;
    }

    Ok(ldap)
}

/// Authenticate a user by attempting to bind with their credentials.
pub async fn authenticate_bind(
    config: &LdapConfig,
    user_dn: &str,
    password: &str,
) -> Result<bool, IdentityDatabaseError> {
    let settings = LdapConnSettings::new()
        .set_conn_timeout(Duration::from_secs(config.timeout))
        .set_starttls(config.use_tls);

    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &config.url)
        .await
        .map_err(|e| IdentityDatabaseError::LdapConnection(e.to_string()))?;

    tokio::spawn(async move {
        if let Err(e) = conn.drive().await {
            tracing::error!("LDAP connection driver error: {}", e);
        }
    });

    // Try to bind with user credentials
    match ldap.simple_bind(user_dn, password).await {
        Ok(result) => match result.success() {
            Ok(_) => {
                // Successful bind - close connection
                let _ = ldap.unbind().await;
                Ok(true)
            }
            Err(_) => Ok(false),
        },
        Err(_) => Ok(false),
    }
}

/// Build search filter from base filter and additional filter if provided.
pub fn build_filter(base_filter: &str, additional_filter: Option<&String>) -> String {
    if let Some(extra) = additional_filter {
        format!("(&{}{})", base_filter, extra)
    } else {
        base_filter.to_string()
    }
}

/// Escape special LDAP characters in a string for use in search filters.
pub fn escape_filter_chars(input: &str) -> String {
    input
        .replace('\\', "\\5c")
        .replace('*', "\\2a")
        .replace('(', "\\28")
        .replace(')', "\\29")
        .replace('\0', "\\00")
}
