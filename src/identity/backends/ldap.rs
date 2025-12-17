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

//! LDAP identity backend implementation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashSet;

pub mod authenticate;
mod connection;
pub mod group;
mod mapping;
pub mod user;
pub mod user_group;

use super::super::types::*;
use crate::auth::AuthenticatedInfo;
use crate::config::Config;
use crate::identity::IdentityProviderError;
use crate::identity::backends::IdentityBackend;
use crate::identity::backends::error::IdentityDatabaseError;
use crate::keystone::ServiceState;

/// LDAP identity backend.
#[derive(Clone, Debug, Default)]
pub struct LdapBackend {
    pub config: Config,
    /// Domain ID for LDAP users/groups (LDAP typically maps to a single domain).
    pub domain_id: String,
}

impl LdapBackend {
    /// Get the LDAP domain ID from resource provider or use default.
    async fn get_domain_id(&self, state: &ServiceState) -> Result<String, IdentityProviderError> {
        // For LDAP, we typically use a configured domain or the default domain
        // In a production implementation, this might be configurable
        if self.domain_id.is_empty() {
            // Use "default" domain or fetch from resource provider
            Ok("default".to_string())
        } else {
            Ok(self.domain_id.clone())
        }
    }
}

#[async_trait]
impl IdentityBackend for LdapBackend {
    fn set_config(&mut self, config: Config) {
        self.config = config;
        // Set default domain ID if not already set
        if self.domain_id.is_empty() {
            self.domain_id = "default".to_string();
        }
    }

    async fn authenticate_by_password(
        &self,
        state: &ServiceState,
        auth: &UserPasswordAuthRequest,
    ) -> Result<AuthenticatedInfo, IdentityProviderError> {
        let domain_id = self.get_domain_id(state).await?;
        Ok(authenticate::authenticate_by_password(&self.config.ldap, auth, &domain_id).await?)
    }

    async fn list_users(
        &self,
        state: &ServiceState,
        params: &UserListParameters,
    ) -> Result<Vec<UserResponse>, IdentityProviderError> {
        let domain_id = self.get_domain_id(state).await?;
        Ok(user::list(&self.config.ldap, params, &domain_id).await?)
    }

    async fn get_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        let domain_id = self.get_domain_id(state).await?;
        Ok(user::get(&self.config.ldap, user_id, &domain_id).await?)
    }

    async fn find_federated_user<'a>(
        &self,
        _state: &ServiceState,
        _idp_id: &'a str,
        _unique_id: &'a str,
    ) -> Result<Option<UserResponse>, IdentityProviderError> {
        // Federated users are not supported in pure LDAP backend
        // This would require a hybrid SQL+LDAP approach
        Ok(None)
    }

    async fn create_user(
        &self,
        state: &ServiceState,
        user: UserCreate,
    ) -> Result<UserResponse, IdentityProviderError> {
        let domain_id = self.get_domain_id(state).await?;
        Ok(user::create(&self.config.ldap, &user.id, &user.name, &domain_id).await?)
    }

    async fn delete_user<'a>(
        &self,
        _state: &ServiceState,
        user_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user::delete(&self.config.ldap, user_id).await?)
    }

    async fn list_groups(
        &self,
        state: &ServiceState,
        params: &GroupListParameters,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        let domain_id = self.get_domain_id(state).await?;
        Ok(group::list(&self.config.ldap, params, &domain_id).await?)
    }

    async fn get_group<'a>(
        &self,
        state: &ServiceState,
        group_id: &'a str,
    ) -> Result<Option<Group>, IdentityProviderError> {
        let domain_id = self.get_domain_id(state).await?;
        Ok(group::get(&self.config.ldap, group_id, &domain_id).await?)
    }

    async fn create_group(
        &self,
        state: &ServiceState,
        group: GroupCreate,
    ) -> Result<Group, IdentityProviderError> {
        let domain_id = self.get_domain_id(state).await?;
        let group_id = group.id.as_ref().ok_or_else(|| {
            IdentityDatabaseError::LdapAttributeMapping("Group ID is required".to_string())
        })?;
        Ok(group::create(&self.config.ldap, group_id, &group.name, &domain_id).await?)
    }

    async fn delete_group<'a>(
        &self,
        _state: &ServiceState,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(group::delete(&self.config.ldap, group_id).await?)
    }

    async fn list_groups_of_user<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
    ) -> Result<Vec<Group>, IdentityProviderError> {
        let domain_id = self.get_domain_id(state).await?;
        Ok(user_group::list_user_groups(&self.config.ldap, user_id, &domain_id).await?)
    }

    async fn add_user_to_group<'a>(
        &self,
        _state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::add_user_to_group(&self.config.ldap, user_id, group_id).await?)
    }

    async fn add_user_to_group_expiring<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_id: &'a str,
        _idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        // Expiring group memberships not supported in pure LDAP
        Err(IdentityDatabaseError::LdapNotSupported(
            "Expiring group memberships require SQL backend".to_string(),
        )
        .into())
    }

    async fn add_users_to_groups<'a>(
        &self,
        _state: &ServiceState,
        memberships: Vec<(&'a str, &'a str)>,
    ) -> Result<(), IdentityProviderError> {
        for (user_id, group_id) in memberships {
            user_group::add_user_to_group(&self.config.ldap, user_id, group_id).await?;
        }
        Ok(())
    }

    async fn add_users_to_groups_expiring<'a>(
        &self,
        _state: &ServiceState,
        _memberships: Vec<(&'a str, &'a str)>,
        _idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        // Expiring group memberships not supported in pure LDAP
        Err(IdentityDatabaseError::LdapNotSupported(
            "Expiring group memberships require SQL backend".to_string(),
        )
        .into())
    }

    async fn remove_user_from_group<'a>(
        &self,
        _state: &ServiceState,
        user_id: &'a str,
        group_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        Ok(user_group::remove_user_from_group(&self.config.ldap, user_id, group_id).await?)
    }

    async fn remove_user_from_group_expiring<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_id: &'a str,
        _idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        // Expiring group memberships not supported in pure LDAP
        Err(IdentityDatabaseError::LdapNotSupported(
            "Expiring group memberships require SQL backend".to_string(),
        )
        .into())
    }

    async fn remove_user_from_groups<'a>(
        &self,
        _state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        for group_id in group_ids {
            user_group::remove_user_from_group(&self.config.ldap, user_id, group_id).await?;
        }
        Ok(())
    }

    async fn remove_user_from_groups_expiring<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_ids: HashSet<&'a str>,
        _idp_id: &'a str,
    ) -> Result<(), IdentityProviderError> {
        // Expiring group memberships not supported in pure LDAP
        Err(IdentityDatabaseError::LdapNotSupported(
            "Expiring group memberships require SQL backend".to_string(),
        )
        .into())
    }

    async fn set_user_groups<'a>(
        &self,
        state: &ServiceState,
        user_id: &'a str,
        group_ids: HashSet<&'a str>,
    ) -> Result<(), IdentityProviderError> {
        // Get current groups
        let current_groups = self.list_groups_of_user(state, user_id).await?;
        let current_group_ids: HashSet<&str> =
            current_groups.iter().map(|g| g.id.as_str()).collect();

        // Add to new groups
        for group_id in &group_ids {
            if !current_group_ids.contains(group_id) {
                user_group::add_user_to_group(&self.config.ldap, user_id, group_id).await?;
            }
        }

        // Remove from old groups
        for group_id in &current_group_ids {
            if !group_ids.contains(group_id) {
                user_group::remove_user_from_group(&self.config.ldap, user_id, group_id).await?;
            }
        }

        Ok(())
    }

    async fn set_user_groups_expiring<'a>(
        &self,
        _state: &ServiceState,
        _user_id: &'a str,
        _group_ids: HashSet<&'a str>,
        _idp_id: &'a str,
        _last_verified: Option<&DateTime<Utc>>,
    ) -> Result<(), IdentityProviderError> {
        // Expiring group memberships not supported in pure LDAP
        Err(IdentityDatabaseError::LdapNotSupported(
            "Expiring group memberships require SQL backend".to_string(),
        )
        .into())
    }
}
