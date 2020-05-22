use crate::prelude::*;
use crate::authentication_manager::ServiceAccount;
use tokio::fs;

#[derive(Debug)]
pub struct CustomServiceAccount {
    tokens: HashMap<Vec<String>, Token>,
    credentials: ApplicationCredentials,
}

impl CustomServiceAccount {
    const GOOGLE_APPLICATION_CREDENTIALS: &'static str = "GOOGLE_APPLICATION_CREDENTIALS";

    pub async fn new() -> Result<Self, GCPAuthError> {
        let path = std::env::var(Self::GOOGLE_APPLICATION_CREDENTIALS).map_err(|_| GCPAuthError::AplicationProfileMissing)?;
        let credentials = ApplicationCredentials::from_file(path).await?;
        Ok(Self {
            credentials,
            tokens: HashMap::new(),
        })
    }
}

#[async_trait]
impl ServiceAccount for CustomServiceAccount {
    fn get_token(&self, scopes: &[&str]) -> Option<Token> {
        let key: Vec<_> = scopes.iter().map(|x| (*x).to_string()).collect();
        let token = self
            .tokens
            .get(&key);
        
        if token.is_none() || token.unwrap().has_expired() {
            return None;
        }
        Some(token.unwrap().clone())
    }

    async fn refresh_token(&mut self, client: &HyperClient, scopes: &[&str]) -> Result<(), GCPAuthError> {
        use crate::jwt::Claims;
        use crate::jwt::JWTSigner;
        use crate::jwt::GRANT_TYPE;
        use hyper::header;
        use url::form_urlencoded;

        let signer = JWTSigner::new(&self.credentials.private_key)?;

        let claims = Claims::new(&self.credentials, scopes, None);
        let signed = signer.sign_claims(&claims).map_err(GCPAuthError::TLSError)?;
        let rqbody = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[("grant_type", GRANT_TYPE), ("assertion", signed.as_str())])
            .finish();
        let request = hyper::Request::post(&self.credentials.token_uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(hyper::Body::from(rqbody))
            .unwrap();
        log::debug!("requesting token from service account: {:?}", request);
        let (head, body) = client.request(request).await.map_err(GCPAuthError::OAuthConnectionError)?.into_parts();
        let body = hyper::body::to_bytes(body).await.map_err(GCPAuthError::OAuthConnectionError)?;
        log::debug!("received response; head: {:?}, body: {:?}", head, body);
        let token: Token = serde_json::from_slice(&body).map_err(GCPAuthError::OAuthParsingError)?;
        let key = scopes.iter().map(|x| (*x).to_string()).collect();
        self.tokens.insert(key, token);
        Ok(())
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
    async fn from_file<T: AsRef<Path>>(path: T) -> Result<ApplicationCredentials, GCPAuthError> {
        let content = fs::read_to_string(path).await.map_err(GCPAuthError::AplicationProfilePath)?;
        Ok(serde_json::from_str(&content).map_err(GCPAuthError::AplicationProfileFormat)?)
    }
}
