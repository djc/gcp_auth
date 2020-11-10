use crate::authentication_manager::ServiceAccount;
use crate::prelude::*;
use std::sync::RwLock;
use tokio::fs;

#[derive(Debug)]
pub struct CustomServiceAccount {
    tokens: RwLock<HashMap<Vec<String>, Token>>,
    credentials: ApplicationCredentials,
}

impl CustomServiceAccount {
    const GOOGLE_APPLICATION_CREDENTIALS: &'static str = "GOOGLE_APPLICATION_CREDENTIALS";

    pub async fn new() -> Result<Self, Error> {
        let path = std::env::var(Self::GOOGLE_APPLICATION_CREDENTIALS)
            .map_err(|_| Error::AplicationProfileMissing)?;
        let credentials = ApplicationCredentials::from_file(path).await?;
        Ok(Self {
            credentials,
            tokens: RwLock::new(HashMap::new()),
        })
    }
}

#[async_trait]
impl ServiceAccount for CustomServiceAccount {
    fn get_token(&self, scopes: &[&str]) -> Option<Token> {
        let key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();
        self.tokens.read().unwrap().get(&key).cloned()
    }

    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        use crate::jwt::Claims;
        use crate::jwt::JWTSigner;
        use crate::jwt::GRANT_TYPE;
        use hyper::header;
        use url::form_urlencoded;

        let signer = JWTSigner::new(&self.credentials.private_key)?;

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
pub struct ApplicationCredentials {
    pub r#type: Option<String>,
    /// project_id
    pub project_id: Option<String>,
    /// private_key_id
    pub private_key_id: Option<String>,
    /// private_key
    pub private_key: String,
    /// client_email
    pub client_email: String,
    /// client_id
    pub client_id: Option<String>,
    /// auth_uri
    pub auth_uri: Option<String>,
    /// token_uri
    pub token_uri: String,
    /// auth_provider_x509_cert_url
    pub auth_provider_x509_cert_url: Option<String>,
    /// client_x509_cert_url
    pub client_x509_cert_url: Option<String>,
}

impl ApplicationCredentials {
    async fn from_file<T: AsRef<Path>>(path: T) -> Result<ApplicationCredentials, Error> {
        let content = fs::read_to_string(path)
            .await
            .map_err(Error::AplicationProfilePath)?;
        Ok(serde_json::from_str(&content).map_err(Error::AplicationProfileFormat)?)
    }
}
