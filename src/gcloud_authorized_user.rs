use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::RwLock;
use std::time::Duration;

use async_trait::async_trait;
use which::which;

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::error::Error::{GCloudError, GCloudNotFound, GCloudParseError};
use crate::types::HyperClient;
use crate::Token;

/// The default number of seconds that it takes for a Google Cloud auth token to expire.
/// This appears to be the default from practical testing, but we have not found evidence
/// that this will always be the default duration.
pub(crate) const DEFAULT_TOKEN_DURATION: Duration = Duration::from_secs(3600);

#[derive(Debug)]
pub(crate) struct GCloudAuthorizedUser {
    gcloud: PathBuf,
    project_id: Option<String>,
    token: RwLock<Token>,
}

impl GCloudAuthorizedUser {
    pub(crate) async fn new() -> Result<Self, Error> {
        let gcloud = which("gcloud").map_err(|_| GCloudNotFound)?;
        let project_id = run(&gcloud, &["config", "get-value", "project"]).ok();
        let token = RwLock::new(Self::token(&gcloud)?);
        Ok(Self {
            gcloud,
            project_id,
            token,
        })
    }

    fn token(gcloud: &Path) -> Result<Token, Error> {
        Ok(Token::from_string(
            run(gcloud, &["auth", "print-access-token", "--quiet"])?,
            DEFAULT_TOKEN_DURATION,
        ))
    }
}

#[async_trait]
impl ServiceAccount for GCloudAuthorizedUser {
    async fn project_id(&self, _: &HyperClient) -> Result<String, Error> {
        self.project_id.clone().ok_or(Error::NoProjectId)
    }

    fn get_token(&self, _scopes: &[&str]) -> Option<Token> {
        Some(self.token.read().unwrap().clone())
    }

    async fn refresh_token(
        &self,
        _client: &HyperClient,
        _scopes: &[&str],
        _subject: Option<&str>,
    ) -> Result<Token, Error> {
        let token = Self::token(&self.gcloud)?;
        *self.token.write().unwrap() = token.clone();
        Ok(token)
    }
}

fn run(gcloud: &Path, cmd: &[&str]) -> Result<String, Error> {
    let mut command = Command::new(gcloud);
    command.args(cmd);

    let mut stdout = match command.output() {
        Ok(output) if output.status.success() => output.stdout,
        _ => return Err(GCloudError),
    };

    while let Some(b' ' | b'\r' | b'\n') = stdout.last() {
        stdout.pop();
    }

    String::from_utf8(stdout).map_err(|_| GCloudParseError)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn gcloud() {
        let gcloud = GCloudAuthorizedUser::new().await.unwrap();
        println!("{:?}", gcloud.project_id);
        if let Some(t) = gcloud.get_token(&[""]) {
            let expires = Utc::now() + DEFAULT_TOKEN_DURATION;
            println!("{:?}", t);
            assert!(!t.has_expired());
            assert!(t.expires_at() < expires + Duration::from_secs(1));
            assert!(t.expires_at() > expires - Duration::from_secs(1));
        } else {
            panic!("GCloud Authorized User failed to get a token");
        }
    }

    /// `gcloud_authorized_user` is the only user type to get a token that isn't deserialized from
    /// JSON, and that doesn't include an expiry time. As such, the default token expiry time
    /// functionality is tested here.
    #[test]
    fn test_token_from_string() {
        let s = String::from("abc123");
        let token = Token::from_string(s, DEFAULT_TOKEN_DURATION);
        let expires = Utc::now() + DEFAULT_TOKEN_DURATION;

        assert_eq!(token.as_str(), "abc123");
        assert!(!token.has_expired());
        assert!(token.expires_at() < expires + Duration::from_secs(1));
        assert!(token.expires_at() > expires - Duration::from_secs(1));
    }

    #[test]
    fn test_deserialize_no_time() {
        let s = r#"{"access_token":"abc123"}"#;
        let result = serde_json::from_str::<Token>(s)
            .expect_err("Deserialization from JSON should fail when no expiry_time is included");

        assert!(result.is_data());
    }
}
