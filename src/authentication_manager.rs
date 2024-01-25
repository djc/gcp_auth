use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tracing::{debug, info, warn};

use crate::custom_service_account::CustomServiceAccount;
use crate::default_authorized_user::ConfigDefaultCredentials;
use crate::default_service_account::MetadataServiceAccount;
use crate::error::Error;
use crate::gcloud_authorized_user::GCloudAuthorizedUser;
use crate::types::{self, HyperClient, Token};

#[async_trait]
pub(crate) trait ServiceAccount: Send + Sync {
    async fn project_id(&self, client: &HyperClient) -> Result<String, Error>;
    fn get_token(&self, scopes: &[&str]) -> Option<Token>;
    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error>;
    fn get_style(&self) -> TokenStyle;
}

pub(crate) enum TokenStyle {
    Account,
    AccountAndScopes,
}

/// Authentication manager is responsible for caching and obtaining credentials for the required
/// scope
///
/// Construct the authentication manager with [`AuthenticationManager::new()`] or by creating
/// a [`CustomServiceAccount`], then converting it into an `AuthenticationManager` using the `From`
/// impl.
#[derive(Clone)]
pub struct AuthenticationManager(Arc<AuthManagerInner>);

struct AuthManagerInner {
    client: HyperClient,
    service_account: Box<dyn ServiceAccount>,
    refresh_lock: RefreshLock,
}

impl AuthenticationManager {
    /// Finds a service account provider to get authentication tokens from
    ///
    /// Tries the following approaches, in order:
    ///
    /// 1. Check if the `GOOGLE_APPLICATION_CREDENTIALS` environment variable if set;
    ///    if so, use a custom service account as the token source.
    /// 2. Look for credentials in `.config/gcloud/application_default_credentials.json`;
    ///    if found, use these credentials to request refresh tokens.
    /// 3. Send a HTTP request to the internal metadata server to retrieve a token;
    ///    if it succeeds, use the default service account as the token source.
    /// 4. Check if the `gcloud` tool is available on the `PATH`; if so, use the
    ///    `gcloud auth print-access-token` command as the token source.
    #[tracing::instrument]
    pub async fn new() -> Result<Self, Error> {
        tracing::debug!("Initializing gcp_auth");
        if let Some(service_account) = CustomServiceAccount::from_env()? {
            return service_account.try_into();
        }

        let client = types::client()?;
        let default_user_error = match ConfigDefaultCredentials::new(&client).await {
            Ok(service_account) => {
                tracing::debug!("Using ConfigDefaultCredentials");
                return Ok(Self::build(client, service_account));
            }
            Err(e) => e,
        };

        let default_service_error = match MetadataServiceAccount::new(&client).await {
            Ok(service_account) => {
                tracing::debug!("Using MetadataServiceAccount");
                return Ok(Self::build(client, service_account));
            }
            Err(e) => e,
        };

        let gcloud_error = match GCloudAuthorizedUser::new().await {
            Ok(service_account) => {
                tracing::debug!("Using GCloudAuthorizedUser");
                return Ok(Self::build(client, service_account));
            }
            Err(e) => e,
        };

        Err(Error::NoAuthMethod(
            Box::new(gcloud_error),
            Box::new(default_service_error),
            Box::new(default_user_error),
        ))
    }

    fn build(client: HyperClient, service_account: impl ServiceAccount + 'static) -> Self {
        let refresh_lock = RefreshLock::new(service_account.get_style());
        Self(Arc::new(AuthManagerInner {
            client,
            service_account: Box::new(service_account),
            refresh_lock,
        }))
    }

    /// Requests Bearer token for the provided scope
    ///
    /// Token can be used in the request authorization header in format "Bearer {token}"
    pub async fn get_token(&self, scopes: &[&str]) -> Result<Token, Error> {
        let token = self.0.service_account.get_token(scopes);

        if let Some(token) = token.filter(|token| !token.has_expired()) {
            let valid_for = token.expires_at().signed_duration_since(Utc::now());
            if valid_for < Duration::seconds(60) {
                debug!(?valid_for, "gcp_auth token expires soon!");

                let lock = self.0.refresh_lock.lock_for_scopes(scopes).await;
                match lock.try_lock_owned() {
                    Err(_) => {
                        // already being refreshed.
                    }
                    Ok(guard) => {
                        let inner = self.clone();
                        let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
                        tokio::spawn(async move {
                            inner.background_refresh(scopes, guard).await;
                        });
                    }
                }
            }
            return Ok(token);
        }

        warn!("starting inline refresh of gcp auth token");
        let lock = self.0.refresh_lock.lock_for_scopes(scopes).await;
        let _guard = lock.lock().await;

        // Check if refresh happened while we were waiting.
        let token = self.0.service_account.get_token(scopes);
        if let Some(token) = token.filter(|token| !token.has_expired()) {
            return Ok(token);
        }

        self.0
            .service_account
            .refresh_token(&self.0.client, scopes)
            .await
    }

    async fn background_refresh(&self, scopes: Vec<String>, _lock: OwnedMutexGuard<()>) {
        info!("gcp_auth starting background refresh of auth token");
        let scope_refs: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
        match self
            .0
            .service_account
            .refresh_token(&self.0.client, &scope_refs)
            .await
        {
            Ok(t) => {
                info!(valid_for=?t.expires_at().signed_duration_since(Utc::now()), "gcp auth completed background token refresh")
            }
            Err(err) => warn!(?err, "gcp_auth background token refresh failed"),
        }
    }

    /// Request the project ID for the authenticating account
    ///
    /// This is only available for service account-based authentication methods.
    pub async fn project_id(&self) -> Result<String, Error> {
        self.0.service_account.project_id(&self.0.client).await
    }
}

impl TryFrom<CustomServiceAccount> for AuthenticationManager {
    type Error = Error;

    fn try_from(service_account: CustomServiceAccount) -> Result<Self, Self::Error> {
        Ok(Self::build(types::client()?, service_account))
    }
}

enum RefreshLock {
    One(Arc<Mutex<()>>),
    ByScopes(Mutex<HashMap<Vec<String>, Arc<Mutex<()>>>>),
}

impl RefreshLock {
    fn new(style: TokenStyle) -> Self {
        match style {
            TokenStyle::Account => RefreshLock::One(Arc::new(Mutex::new(()))),
            TokenStyle::AccountAndScopes => RefreshLock::ByScopes(Mutex::new(HashMap::new())),
        }
    }

    async fn lock_for_scopes(&self, scopes: &[&str]) -> Arc<Mutex<()>> {
        match self {
            RefreshLock::One(mutex) => mutex.clone(),
            RefreshLock::ByScopes(mutexes) => {
                let scopes_key: Vec<_> = scopes.iter().map(|s| s.to_string()).collect();
                let mut scope_locks = mutexes.lock().await;
                match scope_locks.entry(scopes_key) {
                    Occupied(e) => e.get().clone(),
                    Vacant(v) => {
                        let lock = Arc::new(Mutex::new(()));
                        v.insert(lock.clone());
                        lock
                    }
                }
            }
        }
    }
}
