use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::custom_service_account::CustomServiceAccount;
use crate::default_authorized_user::DefaultAuthorizedUser;
use crate::default_service_account::DefaultServiceAccount;
use crate::error::Error;
use crate::gcloud_authorized_user::GCloudAuthorizedUser;
use crate::types::{self, HyperClient, Token};

#[async_trait]
pub(crate) trait ServiceAccount: Send + Sync {
    async fn project_id(&self, client: &HyperClient) -> Result<String, Error>;
    fn get_token(&self, scopes: &[&str]) -> Option<Token>;
    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error>;
}

/// Authentication manager is responsible for caching and obtaing credentials for the required scope
///
/// Cacheing for the full life time is ensured
pub struct AuthenticationManager {
    pub(crate) client: HyperClient,
    pub(crate) service_account: Box<dyn ServiceAccount>,
    refresh_mutex: Mutex<()>,
}

impl AuthenticationManager {
    pub(crate) async fn select(
        custom: Option<CustomServiceAccount>,
    ) -> Result<AuthenticationManager, Error> {
        let client = types::client();

        if let Some(service_account) = custom {
            log::debug!("Using CustomServiceAccount");
            return Ok(Self::new(client, service_account));
        }

        let gcloud_error = match GCloudAuthorizedUser::new() {
            Ok(service_account) => {
                log::debug!("Using GCloudAuthorizedUser");
                return Ok(Self::new(client, service_account));
            }
            Err(e) => e,
        };

        let default_service_error = match DefaultServiceAccount::new(&client).await {
            Ok(service_account) => {
                log::debug!("Using DefaultServiceAccount");
                return Ok(Self::new(client, service_account));
            }
            Err(e) => e,
        };

        let default_user_error = match DefaultAuthorizedUser::new(&client).await {
            Ok(service_account) => {
                log::debug!("Using DefaultAuthorizedUser");
                return Ok(Self::new(client, service_account));
            }
            Err(e) => e,
        };

        Err(Error::NoAuthMethod(
            Box::new(gcloud_error),
            Box::new(default_service_error),
            Box::new(default_user_error),
        ))
    }

    fn new(client: HyperClient, service_account: impl ServiceAccount + 'static) -> Self {
        Self {
            client,
            service_account: Box::new(service_account),
            refresh_mutex: Mutex::new(()),
        }
    }

    /// Requests Bearer token for the provided scope
    ///
    /// Token can be used in the request authorization header in format "Bearer {token}"
    pub async fn get_token(&self, scopes: &[&str]) -> Result<Token, Error> {
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

        self.service_account
            .refresh_token(&self.client, scopes)
            .await
    }

    /// Request the project ID for the authenticating account
    ///
    /// This is only available for service account-based authentication methods.
    pub async fn project_id(&self) -> Result<String, Error> {
        self.service_account.project_id(&self.client).await
    }
}
