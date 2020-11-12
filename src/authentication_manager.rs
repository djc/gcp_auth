use crate::prelude::*;

#[async_trait]
pub trait ServiceAccount: Send + Sync {
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
}

impl AuthenticationManager {
    /// Requests Bearer token for the provided scope
    ///
    /// Token can be used in the request authorization header in format "Bearer {token}"
    pub async fn get_token(&self, scopes: &[&str]) -> Result<Token, Error> {
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
