use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::RwLock,
};

use async_trait::async_trait;
use hyper::{header, Body, Method, Request};
use serde::{Deserialize, Serialize};
use tokio::fs;

use crate::{
    authentication_manager::ServiceAccount, gcloud_authorized_user::DEFAULT_TOKEN_DURATION,
    types::HyperClient, util::HyperExt, Error, Signer, Token,
};

// Implementation referenced from
// https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/google.go#L158
// Currently not implementing external account credentials
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
enum FlexibleCredentialSource {
    ServiceAccount(ServiceAccountCredentials),
    AuthorizedUser(UserCredentials),
    ImpersonatedServiceAccount(ImpersonatedServiceAccountCredentials),
}

// Refresh logic: https://github.com/golang/oauth2/blob/2e4a4e2bfb69ca7609cb423438c55caa131431c1/jwt/jwt.go#L101
#[derive(Serialize, Debug)]
struct ServiceAccountCredentials {
    audience: Option<String>,
    client_email: String,
    private_key: String,
    private_key_id: String,
    auth_uri: Option<String>,
    token_uri: Option<String>,
    quota_project_id: Option<String>,
    project_id: Option<String>,
    #[serde(skip_serializing)]
    signer: Signer,
}

impl<'de> Deserialize<'de> for ServiceAccountCredentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ServiceAccountCredentialsDeserializer {
            client_email: String,
            private_key: String,
            private_key_id: String,
            token_uri: Option<String>,
            auth_uri: Option<String>,
            audience: Option<String>,
            project_id: Option<String>,
            quota_project_id: Option<String>,
        }

        let deserialized = ServiceAccountCredentialsDeserializer::deserialize(deserializer)?;

        let signer = Signer::new(&deserialized.private_key).map_err(|e| {
            serde::de::Error::custom(format!("failed to create signer from private key: {}", e))
        })?;

        Ok(ServiceAccountCredentials {
            audience: deserialized.audience,
            client_email: deserialized.client_email,
            private_key: deserialized.private_key,
            private_key_id: deserialized.private_key_id,
            token_uri: deserialized.token_uri,
            quota_project_id: deserialized.quota_project_id,
            auth_uri: deserialized.auth_uri,
            project_id: deserialized.project_id,
            signer,
        })
    }
}

impl ServiceAccountCredentials {
    const DEFAULT_TOKEN_URI: &'static str = "https://oauth2.googleapis.com/token";

    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        use crate::jwt::Claims;
        use crate::jwt::GRANT_TYPE;
        use url::form_urlencoded;

        let token_uri = self.token_uri.as_deref().unwrap_or(Self::DEFAULT_TOKEN_URI);
        // https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/jwt/jwt.go#L68
        let audience = self.audience.as_deref().unwrap_or(token_uri);

        let jwt = Claims::new(&self.client_email, &audience, scopes, None).to_jwt(&self.signer)?;
        let rqbody = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(&[("grant_type", GRANT_TYPE), ("assertion", jwt.as_str())])
            .finish();

        let mut retries = 0;
        let response = loop {
            let request = hyper::Request::post(token_uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(hyper::Body::from(rqbody.clone()))
                .unwrap();

            tracing::debug!("requesting token from service account: {request:?}");
            let err = match client.request(request).await {
                // Early return when the request succeeds
                Ok(response) => break response,
                Err(err) => err,
            };

            tracing::warn!(
                "Failed to refresh token with GCP oauth2 token endpoint: {err}, trying again..."
            );
            retries += 1;
            if retries >= RETRY_COUNT {
                return Err(Error::OAuthConnectionError(err));
            }
        };

        Ok(response.deserialize::<Token>().await?)
    }
}

// This credential parses the `~/.config/gcloud/application_default_credentials.json` file
// Will use token_uri if present, otherwise will use `DEFAULT_TOKEN_GCP_URI`
// Refresh logic is a bit nested, but it starts here https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/token.go#L166
#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserCredentials {
    client_id: String,
    client_secret: String,
    token_uri: Option<String>,
    refresh_token: String,
    quota_project_id: Option<String>,
}

impl UserCredentials {
    const DEFAULT_TOKEN_GCP_URI: &'static str = "https://accounts.google.com/o/oauth2/token";

    fn build_token_request(&self) -> Request<Body> {
        #[derive(Serialize, Debug)]
        struct RefreshRequest<'a> {
            client_id: &'a str,
            client_secret: &'a str,
            grant_type: &'a str,
            refresh_token: &'a str,
        }

        Request::builder()
            .method(Method::POST)
            .uri(
                self.token_uri
                    .as_deref()
                    .unwrap_or(Self::DEFAULT_TOKEN_GCP_URI),
            )
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&RefreshRequest {
                    client_id: &self.client_id,
                    client_secret: &self.client_secret,
                    grant_type: "refresh_token",
                    refresh_token: &self.refresh_token,
                })
                .unwrap(),
            ))
            .unwrap()
    }

    async fn refresh_token(&self, client: &HyperClient) -> Result<Token, Error> {
        let mut retries = 0;
        let response = loop {
            let req = self.build_token_request();

            let err = match client.request(req).await {
                // Early return when the request succeeds
                Ok(response) => break response,
                Err(err) => err,
            };

            tracing::warn!(
                "Failed to get token from GCP oauth2 token endpoint: {err}, trying again..."
            );
            retries += 1;
            if retries >= RETRY_COUNT {
                return Err(Error::OAuthConnectionError(err));
            }
        };

        Ok(response.deserialize().await.map_err(Into::<Error>::into)?)
    }
}

// This credential uses the `source_credentials` to get a token
// and then uses that token to get a token impersonating the service
// account specified by `service_account_impersonation_url`.
// refresh logic https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/internal/externalaccount/impersonate.go#L57
#[derive(Serialize, Deserialize, Debug)]
struct ImpersonatedServiceAccountCredentials {
    service_account_impersonation_url: String,
    source_credentials: Box<FlexibleCredentialSource>,
    delegates: Vec<String>,
}

impl ImpersonatedServiceAccountCredentials {
    async fn refresh_with_token(
        &self,
        client: &HyperClient,
        scopes: &[&str],
        source_token: &Token,
    ) -> Result<Token, Error> {
        // Then we do a request to get the impersonated token
        let lifetime_seconds = DEFAULT_TOKEN_DURATION.whole_seconds();
        #[derive(Serialize, Clone)]
        // Format from https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/internal/externalaccount/impersonate.go#L21
        struct AccessTokenRequest {
            lifetime: String,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            scope: Vec<String>,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            delegates: Vec<String>,
        }

        let request = AccessTokenRequest {
            lifetime: format!("{lifetime_seconds}s"),
            scope: scopes.iter().map(|s| s.to_string()).collect(),
            delegates: self.delegates.clone(),
        };
        let rqbody =
            serde_json::to_string(&request).expect("access token request failed to serialize");

        let token_uri = self.service_account_impersonation_url.as_str();

        let mut retries = 0;
        let response = loop {
            // We assume bearer tokens only. In the referenced code, other token types are possible
            // https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/token.go#L84
            let request = hyper::Request::post(token_uri)
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", source_token.as_str()),
                )
                .header(header::CONTENT_TYPE, "application/json")
                .body(hyper::Body::from(rqbody.clone()))
                .unwrap();

            tracing::debug!("requesting impersonation token from service account: {request:?}");
            let err = match client.request(request).await {
                // Early return when the request succeeds
                Ok(response) => break response,
                Err(err) => err,
            };

            tracing::warn!(
                "Failed to refresh impersonation token with service token endpoint {token_uri}: {err}, trying again..."
            );
            retries += 1;
            if retries >= RETRY_COUNT {
                return Err(Error::OAuthConnectionError(err));
            }
        };

        Ok(response.deserialize::<Token>().await?)
    }
}

#[derive(Debug)]
pub(crate) struct FlexibleCredentials {
    tokens: RwLock<HashMap<Vec<String>, Token>>,
    credentials: FlexibleCredentialSource,
    project_id: Option<String>,
}

impl FlexibleCredentials {
    const USER_CREDENTIALS_PATH: &'static str =
        ".config/gcloud/application_default_credentials.json";

    pub(crate) async fn from_env() -> Result<Option<Self>, Error> {
        let creds_path = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS");
        if let Some(path) = creds_path {
            tracing::debug!("Reading credentials file from GOOGLE_APPLICATION_CREDENTIALS env var");
            let creds = Self::from_file(PathBuf::from(path)).await?;
            Ok(Some(creds))
        } else {
            Ok(None)
        }
    }

    /// Read service account credentials from the given JSON file
    async fn from_file<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let creds_string = fs::read_to_string(&path)
            .await
            .map_err(Error::UserProfilePath)?;

        Self::from_json(&creds_string)
    }

    fn from_json(json: &str) -> Result<Self, Error> {
        match serde_json::from_str::<FlexibleCredentialSource>(json) {
            Ok(credentials) => Ok(credentials.into()),
            Err(e) => Err(Error::CustomServiceAccountCredentials(e)),
        }
    }

    pub(crate) async fn from_default_credentials() -> Result<Self, Error> {
        tracing::debug!("Loading user credentials file");
        let mut home = dirs_next::home_dir().ok_or(Error::NoHomeDir)?;
        home.push(Self::USER_CREDENTIALS_PATH);
        Self::from_file(home).await
    }
}

impl FlexibleCredentialSource {
    fn project_id(&self) -> Option<String> {
        return match self {
            FlexibleCredentialSource::ServiceAccount(sac) => sac
                .quota_project_id
                .as_ref()
                .or(sac.project_id.as_ref())
                .cloned(),
            FlexibleCredentialSource::AuthorizedUser(auc) => auc.quota_project_id.clone(),
            FlexibleCredentialSource::ImpersonatedServiceAccount(isc) => {
                isc.source_credentials.project_id()
            }
        };
    }

    #[tracing::instrument]
    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        let token = match self {
            FlexibleCredentialSource::ServiceAccount(creds) => {
                creds.refresh_token(client, scopes).await?
            }
            FlexibleCredentialSource::AuthorizedUser(creds) => creds.refresh_token(client).await?,
            FlexibleCredentialSource::ImpersonatedServiceAccount(isc) => {
                // We don't account for nested impersonation, otherwise we would need async recursion which
                // gets messy
                let source_token = match isc.source_credentials.as_ref() {
                    FlexibleCredentialSource::ServiceAccount(sac) => {
                        sac.refresh_token(client, scopes).await?
                    }
                    FlexibleCredentialSource::AuthorizedUser(auc) => {
                        auc.refresh_token(client).await?
                    }
                    _ => return Err(Error::NestedImpersonation),
                };

                isc.refresh_with_token(client, scopes, &source_token)
                    .await?
            }
        };
        Ok(token)
    }
}

impl From<FlexibleCredentialSource> for FlexibleCredentials {
    fn from(creds: FlexibleCredentialSource) -> Self {
        let pid = creds.project_id();
        FlexibleCredentials {
            tokens: RwLock::new(HashMap::new()),
            credentials: creds,
            project_id: pid,
        }
    }
}

#[async_trait]
impl ServiceAccount for FlexibleCredentials {
    async fn project_id(&self, _hc: &HyperClient) -> Result<String, Error> {
        match &self.project_id {
            Some(project_id) => Ok(project_id.clone()),
            None => Err(Error::ProjectIdNotFound),
        }
    }

    fn get_token(&self, scopes: &[&str]) -> Option<Token> {
        let mut key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();
        key.sort();
        self.tokens.read().unwrap().get(&key).cloned()
    }

    #[tracing::instrument]
    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        let token = self.credentials.refresh_token(client, scopes).await?;
        let mut key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();
        key.sort();
        self.tokens.write().unwrap().insert(key, token.clone());

        Ok(token)
    }
}

/// How many times to attempt to fetch a token from the set credentials token endpoint.
const RETRY_COUNT: u8 = 5;

#[cfg(test)]
mod tests {
    use crate::{authentication_manager::ServiceAccount, types};

    #[tokio::test]
    async fn test_parse_application_default_credentials() {
        let test_creds = r#"{
            "client_id": "***id***.apps.googleusercontent.com",
            "client_secret": "***secret***",
            "quota_project_id": "test_project",
            "refresh_token": "***refresh***",
            "type": "authorized_user"
        }"#;

        let creds =
            super::FlexibleCredentials::from_json(test_creds).expect("Valid creds to parse");

        let client = types::client();
        assert_eq!(
            creds
                .project_id(&client)
                .await
                .expect("Project ID to be present"),
            "test_project".to_string(),
            "Project ID should be parsed"
        );
    }

    #[tokio::test]

    async fn test_parse_impersonating_service_account() {
        let test_creds = r#"{
            "delegates": [],
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test_account@test_project.iam.gserviceaccount.com:generateAccessToken",
            "source_credentials": {
                "client_id": "***id***.apps.googleusercontent.com",
                "client_secret": "***secret***",
                "refresh_token": "***refresh***",
                "type": "authorized_user"
            },
            "type": "impersonated_service_account"
        }"#;

        let creds =
            super::FlexibleCredentials::from_json(test_creds).expect("Valid creds to parse");

        let client = types::client();
        assert!(
            matches!(
                creds
                    .project_id(&client)
                    .await
                    .expect_err("Project ID to not be present"),
                crate::Error::ProjectIdNotFound,
            ),
            "Project id should not be found here",
        );

        assert!(matches!(
            creds.credentials,
            super::FlexibleCredentialSource::ImpersonatedServiceAccount(_)
        ));
    }

    #[tokio::test]
    async fn test_parse_service_account_key() {
        // Don't worry, even though the key is a real private_key, it's not used for anything
        let test_creds = r#" {
            "type": "service_account",
            "project_id": "test_project",
            "private_key_id": "***key_id***",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
            "client_email": "test_account@test.iam.gserviceaccount.com",
            "client_id": "***id***",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test_account%40test.iam.gserviceaccount.com",
            "universe_domain": "googleapis.com"
        }"#;

        let creds =
            super::FlexibleCredentials::from_json(test_creds).expect("Valid creds to parse");

        let client = types::client();
        assert_eq!(
            creds
                .project_id(&client)
                .await
                .expect("Project ID to be present"),
            "test_project".to_string(),
            "Project ID should be parsed"
        );

        assert!(matches!(
            creds.credentials,
            super::FlexibleCredentialSource::ServiceAccount(_)
        ));
    }

    #[tokio::test]
    async fn test_additional_service_account_keys() {
        // Using test cases from https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/google_test.go#L40
        // We have to use a real private key because we validate private keys on parsing as well.
        let k1 = r#"{
            "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
            "client_email": "gopher@developer.gserviceaccount.com",
            "client_id": "gopher.apps.googleusercontent.com",
            "token_uri": "https://accounts.google.com/o/gophers/token",
            "type": "service_account",
            "audience": "https://testservice.googleapis.com/"
        }"#;

        let creds = super::FlexibleCredentials::from_json(k1).expect("Valid creds to parse");

        let client = types::client();
        assert!(
            matches!(
                creds
                    .project_id(&client)
                    .await
                    .expect_err("Project ID to not be present"),
                crate::Error::ProjectIdNotFound,
            ),
            "Project id should not be found here",
        );

        assert!(matches!(
            creds.credentials,
            super::FlexibleCredentialSource::ServiceAccount(_)
        ));

        let k2 = r#"{
            "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
            "client_email": "gopher@developer.gserviceaccount.com",
            "client_id": "gopher.apps.googleusercontent.com",
            "type": "service_account"
        }"#;

        let creds = super::FlexibleCredentials::from_json(k2).expect("Valid creds to parse");

        assert!(
            matches!(
                creds
                    .project_id(&client)
                    .await
                    .expect_err("Project ID to not be present"),
                crate::Error::ProjectIdNotFound,
            ),
            "Project id should not be found here",
        );

        assert!(matches!(
            creds.credentials,
            super::FlexibleCredentialSource::ServiceAccount(_)
        ));

        let k3 = r#"{
            "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
            "client_email": "gopher@developer.gserviceaccount.com",
            "client_id": "gopher.apps.googleusercontent.com",
            "token_uri": "https://accounts.google.com/o/gophers/token",
            "type": "service_account"
        }"#;

        let creds = super::FlexibleCredentials::from_json(k3).expect("Valid creds to parse");

        assert!(
            matches!(
                creds
                    .project_id(&client)
                    .await
                    .expect_err("Project ID to not be present"),
                crate::Error::ProjectIdNotFound,
            ),
            "Project id should not be found here",
        );

        assert!(matches!(
            creds.credentials,
            super::FlexibleCredentialSource::ServiceAccount(_)
        ));
    }
}

// TODO: Add tests from here https://github.com/golang/oauth2/blob/master/google/google_test.go
