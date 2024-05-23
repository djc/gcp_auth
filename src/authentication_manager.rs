use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tracing::{instrument, Level};

use crate::custom_service_account::CustomServiceAccount;
use crate::default_authorized_user::ConfigDefaultCredentials;
use crate::default_service_account::MetadataServiceAccount;
use crate::error::Error;
use crate::gcloud_authorized_user::GCloudAuthorizedUser;
use crate::types::{self, Token};

#[async_trait]
pub(crate) trait ServiceAccount: Send + Sync {
    async fn project_id(&self) -> Result<String, Error>;
    fn get_token(&self, scopes: &[&str]) -> Option<Arc<Token>>;
    async fn refresh_token(&self, scopes: &[&str]) -> Result<Arc<Token>, Error>;
}

/// Authentication manager is responsible for caching and obtaining credentials for the required
/// scope
///
/// Construct the authentication manager with [`AuthenticationManager::new()`] or by creating
/// a [`CustomServiceAccount`], then converting it into an `AuthenticationManager` using the `From`
/// impl.
pub struct AuthenticationManager {
    pub(crate) service_account: Box<dyn ServiceAccount>,
    refresh_mutex: Mutex<()>,
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
    #[instrument(level = Level::DEBUG)]
    pub async fn new() -> Result<Self, Error> {
        tracing::debug!("Initializing gcp_auth");
        if let Some(service_account) = CustomServiceAccount::from_env()? {
            return service_account.try_into();
        }

        let client = types::client()?;
        let default_user_error = match ConfigDefaultCredentials::new(&client).await {
            Ok(service_account) => {
                tracing::debug!("Using ConfigDefaultCredentials");
                return Ok(Self::build(service_account));
            }
            Err(e) => e,
        };

        let default_service_error = match MetadataServiceAccount::new(&client).await {
            Ok(service_account) => {
                tracing::debug!("Using MetadataServiceAccount");
                return Ok(Self::build(service_account));
            }
            Err(e) => e,
        };

        let gcloud_error = match GCloudAuthorizedUser::new().await {
            Ok(service_account) => {
                tracing::debug!("Using GCloudAuthorizedUser");
                return Ok(Self::build(service_account));
            }
            Err(e) => e,
        };

        Err(Error::NoAuthMethod(
            Box::new(gcloud_error),
            Box::new(default_service_error),
            Box::new(default_user_error),
        ))
    }

    fn build(service_account: impl ServiceAccount + 'static) -> Self {
        Self {
            service_account: Box::new(service_account),
            refresh_mutex: Mutex::new(()),
        }
    }

    /// Requests Bearer token for the provided scope
    ///
    /// Token can be used in the request authorization header in format "Bearer {token}"
    pub async fn get_token(&self, scopes: &[&str]) -> Result<Arc<Token>, Error> {
        let token = self.service_account.get_token(scopes);
        if let Some(token) = token.filter(|token| !token.has_expired()) {
            return Ok(token);
        }

        let _guard = self.refresh_mutex.lock().await;

        // Check if refresh happened while we were waiting.
        let token = self.service_account.get_token(scopes);
        if let Some(token) = token.filter(|token| !token.has_expired()) {
            return Ok(token);
        }

        self.service_account.refresh_token(scopes).await
    }

    /// Request the project ID for the authenticating account
    ///
    /// This is only available for service account-based authentication methods.
    pub async fn project_id(&self) -> Result<String, Error> {
        self.service_account.project_id().await
    }
}

impl TryFrom<CustomServiceAccount> for AuthenticationManager {
    type Error = Error;

    fn try_from(service_account: CustomServiceAccount) -> Result<Self, Self::Error> {
        Ok(Self::build(service_account))
    }
}
