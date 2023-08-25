use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::custom_service_account::CustomServiceAccount;
use crate::default_authorized_user::ConfigDefaultCredentials;
use crate::default_service_account::MetadataServiceAccount;
use crate::error::Error;
use crate::gcloud_authorized_user::GCloudAuthorizedUser;
use crate::types::{self, CredentialSource, HyperClient, Token};

#[async_trait]
pub(crate) trait ServiceAccount: Send + Sync {
    async fn project_id(&self, client: &HyperClient) -> Result<String, Error>;
    fn get_token(&self, scopes: &[&str]) -> Option<Token>;
    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error>;
}

/// Authentication manager is responsible for caching and obtaining credentials for the required
/// scope
///
/// Construct the authentication manager with [`AuthenticationManager::new()`] or by creating
/// a [`CustomServiceAccount`], then converting it into an `AuthenticationManager` using the `From`
/// impl.
pub struct AuthenticationManager {
    pub(crate) client: HyperClient,
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
    #[tracing::instrument]
    pub async fn new() -> Result<Self, Error> {
        tracing::debug!("Initializing gcp_auth");
        let client = types::client();
        if let Some(service_account_creds) = CredentialSource::from_env().await? {
            tracing::debug!("Using GOOGLE_APPLICATION_CREDENTIALS env");

            let service_account: Box<dyn ServiceAccount> = match service_account_creds {
                CredentialSource::ServiceAccount(creds) => {
                    let service_account = CustomServiceAccount::new(creds)?;
                    Box::new(service_account)
                }
                CredentialSource::AuthorizedUser(creds) => {
                    let service_account =
                        ConfigDefaultCredentials::from_user_credentials(creds, &client).await?;
                    Box::new(service_account)
                }
            };

            return Ok(Self {
                service_account,
                client,
                refresh_mutex: Mutex::new(()),
            });
        }

        let default_user_error = match CredentialSource::from_default_credentials().await {
            Ok(service_account_creds) => {
                tracing::debug!("Using ConfigDefaultCredentials");

                let service_account: Result<Box<dyn ServiceAccount>, Error> =
                    match service_account_creds {
                        CredentialSource::AuthorizedUser(creds) => {
                            ConfigDefaultCredentials::from_user_credentials(creds, &client)
                                .await
                                .map(|creds| Box::new(creds) as _)
                        }
                        CredentialSource::ServiceAccount(creds) => {
                            CustomServiceAccount::new(creds).map(|creds| Box::new(creds) as _)
                        }
                    };

                match service_account {
                    Ok(service_account) => {
                        return Ok(Self {
                            service_account,
                            client,
                            refresh_mutex: Mutex::new(()),
                        });
                    }
                    Err(e) => e,
                }
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

impl From<CustomServiceAccount> for AuthenticationManager {
    fn from(service_account: CustomServiceAccount) -> Self {
        Self::build(types::client(), service_account)
    }
}
