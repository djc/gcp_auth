use crate::prelude::*;
use std::sync::Mutex;

#[async_trait]
pub trait ServiceAccount: Send {
    fn get_token(&self, scopes: &[&str]) -> Option<Token>;
    async fn refresh_token(&mut self, client: &HyperClient, scopes: &[&str]) -> Result<(), Error>;
}

/// Authentication manager is responsible for caching and obtaing credentials for the required scope
///
/// Cacheing for the full life time is ensured
pub struct AuthenticationManager {
    pub(crate) client: HyperClient,
    pub(crate) service_account: Mutex<Box<dyn ServiceAccount>>,
}

impl AuthenticationManager {
    /// Requests Bearer token for the provided scope
    ///
    /// Token can be used in the request authorization header in format "Bearer {token}"
    pub async fn get_token(&self, scopes: &[&str]) -> Result<Token, Error> {
        let mut sa = self.service_account.lock().unwrap();
        let mut token = sa.get_token(scopes);

        if token.is_none() || token.clone().unwrap().has_expired() {
            sa.refresh_token(&self.client, scopes).await?;
            token = sa.get_token(scopes);
        }

        Ok(token.expect("Token obtained with refresh or failed before"))
    }
}
