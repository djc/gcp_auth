use async_trait::async_trait;
use std::{collections::HashMap, sync::RwLock};
use time::{format_description::well_known::Iso8601, OffsetDateTime};

use hyper::header;
use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    authentication_manager::ServiceAccount, gcloud_authorized_user::DEFAULT_TOKEN_DURATION,
    types::HyperClient, util::HyperExt, Error, Token,
};

// This credential uses the `source_credentials` to get a token
// and then uses that token to get a token impersonating the service
// account specified by `service_account_impersonation_url`.
// refresh logic https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/internal/externalaccount/impersonate.go#L57
//
// In practice, the api currently referred to by `service_account_impersonation_url` is
// https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
pub(crate) struct ImpersonatedServiceAccount {
    service_account_impersonation_url: String,
    source_credentials: Box<dyn ServiceAccount>,
    delegates: Vec<String>,
    tokens: RwLock<HashMap<Vec<String>, Token>>,
}

impl ImpersonatedServiceAccount {
    pub(crate) fn new(
        source_credentials: Box<dyn ServiceAccount>,
        service_account_impersonation_url: String,
        delegates: Vec<String>,
    ) -> Self {
        Self {
            service_account_impersonation_url,
            source_credentials,
            delegates,
            tokens: RwLock::new(HashMap::new()),
        }
    }
}

impl std::fmt::Debug for ImpersonatedServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImpersonatedServiceAccount")
            .field(
                "service_account_impersonation_url",
                &self.service_account_impersonation_url,
            )
            .field("source_credentials", &"Box<dyn ServiceAccount>")
            .field("delegates", &self.delegates)
            .finish()
    }
}

// This is the impersonation token described by this documentation
// https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImpersonationTokenResponse {
    access_token: String,
    #[serde(deserialize_with = "deserialize_rfc3339")]
    expire_time: OffsetDateTime,
}

fn deserialize_rfc3339<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    // First try to deserialize seconds
    let time_str: String = Deserialize::deserialize(deserializer)?;

    OffsetDateTime::parse(&time_str, &Iso8601::PARSING).map_err(de::Error::custom)
}

impl From<ImpersonationTokenResponse> for Token {
    fn from(value: ImpersonationTokenResponse) -> Self {
        Token::new(value.access_token, value.expire_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_impersonation_token() {
        let resp_body = "{\n  \"accessToken\": \"secret_token\",\n  \"expireTime\": \"2023-08-18T04:09:45Z\"\n}";
        let token: ImpersonationTokenResponse =
            serde_json::from_str(resp_body).expect("Failed to parse token");
        assert_eq!(token.access_token, "secret_token");
    }
}

#[async_trait]
impl ServiceAccount for ImpersonatedServiceAccount {
    async fn project_id(&self, hc: &HyperClient) -> Result<String, Error> {
        self.source_credentials.project_id(hc).await
    }

    fn get_token(&self, scopes: &[&str]) -> Option<Token> {
        let key: Vec<_> = scopes.iter().map(|x| x.to_string()).collect();
        self.tokens.read().unwrap().get(&key).cloned()
    }

    async fn refresh_token(&self, client: &HyperClient, scopes: &[&str]) -> Result<Token, Error> {
        let source_token = self
            .source_credentials
            .refresh_token(client, scopes)
            .await?;

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

        let token_response: ImpersonationTokenResponse = response.deserialize().await?;
        let token: Token = token_response.into();

        let key = scopes.iter().map(|x| (*x).to_string()).collect();
        self.tokens.write().unwrap().insert(key, token.clone());

        Ok(token)
    }
}

/// How many times to attempt to fetch a token from the set credentials token endpoint.
const RETRY_COUNT: u8 = 5;
