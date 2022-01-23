use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::types::{HyperClient, Token};
use crate::util::HyperExt;

#[derive(Debug)]
pub(crate) struct CustomServiceAccount {
    tokens: RwLock<HashMap<Vec<String>, Token>>,
    credentials: ApplicationCredentials,
}

impl CustomServiceAccount {
    pub(crate) async fn from_file(path: &Path) -> Result<Self, Error> {
        Ok(Self {
            credentials: ApplicationCredentials::from_file(path).await?,
            tokens: RwLock::new(HashMap::new()),
        })
    }

    pub(crate) fn from_json(s: &str) -> Result<Self, Error> {
        Ok(Self {
            credentials: ApplicationCredentials::from_json(s)?,
            tokens: RwLock::new(HashMap::new()),
        })
    }
}

#[async_trait]
impl ServiceAccount for CustomServiceAccount {
    async fn project_id(&self, _: &HyperClient) -> Result<String, Error> {
        match &self.credentials.project_id {
            Some(pid) => Ok(pid.clone()),
            None => Err(Error::ProjectIdNotFound),
        }
    }

    fn get_token(&self, scopes: &[&str]) -> Option<Token> {
        let key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();
        self.tokens.read().unwrap().get(&key).cloned()
    }

    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        use crate::jwt::Claims;
        use crate::jwt::JwtSigner;
        use crate::jwt::GRANT_TYPE;
        use hyper::header;
        use url::form_urlencoded;

        let signer = JwtSigner::new(&self.credentials.private_key)?;

        let claims = Claims::new(&self.credentials, scopes, None);
        let signed = signer.sign_claims(&claims).map_err(Error::TLSError)?;
        let rqbody = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[("grant_type", GRANT_TYPE), ("assertion", signed.as_str())])
            .finish();
        let request = hyper::Request::post(&self.credentials.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(rqbody))
            .unwrap();
        log::debug!("requesting token from service account: {:?}", request);
        let token = client
            .request(request)
            .await
            .map_err(Error::OAuthConnectionError)?
            .deserialize::<Token>()
            .await?;
        let key = scopes.iter().map(|x| (*x).to_string()).collect();
        self.tokens.write().unwrap().insert(key, token.clone());
        Ok(token)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct ApplicationCredentials {
    pub(crate) r#type: Option<String>,
    /// project_id
    pub(crate) project_id: Option<String>,
    /// private_key_id
    pub(crate) private_key_id: Option<String>,
    /// private_key
    pub(crate) private_key: String,
    /// client_email
    pub(crate) client_email: String,
    /// client_id
    pub(crate) client_id: Option<String>,
    /// auth_uri
    pub(crate) auth_uri: Option<String>,
    /// token_uri
    pub(crate) token_uri: String,
    /// auth_provider_x509_cert_url
    pub(crate) auth_provider_x509_cert_url: Option<String>,
    /// client_x509_cert_url
    pub(crate) client_x509_cert_url: Option<String>,
}

impl ApplicationCredentials {
    async fn from_file<T: AsRef<Path>>(path: T) -> Result<ApplicationCredentials, Error> {
        let content = fs::read_to_string(path)
            .await
            .map_err(Error::ApplicationProfilePath)?;
        ApplicationCredentials::from_json(&content)
    }

    fn from_json(s: &str) -> Result<ApplicationCredentials, Error> {
        Ok(serde_json::from_str(s).map_err(Error::ApplicationProfileFormat)?)
    }
}
