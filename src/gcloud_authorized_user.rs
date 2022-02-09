use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::error::Error::{GCloudError, GCloudNotFound, GCloudParseError, ParsingError};
use crate::types::HyperClient;
use crate::Token;
use async_trait::async_trait;
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;
use which::which;

#[derive(Debug)]
pub(crate) struct GCloudAuthorizedUser {
    gcloud: PathBuf,
}

impl GCloudAuthorizedUser {
    pub(crate) fn new() -> Result<Self, Error> {
        which("gcloud")
            .map_err(|_| GCloudNotFound)
            .map(|path| Self { gcloud: path })
    }
}

#[async_trait]
impl ServiceAccount for GCloudAuthorizedUser {
    async fn project_id(&self, _: &HyperClient) -> Result<String, Error> {
        let mut command = Command::new(&self.gcloud);
        command.args(&["config", "get-value", "project"]);

        match command.output() {
            Ok(output) if output.status.success() => {
                let mut line = output.stdout;
                while let Some(b' ' | b'\r' | b'\n') = line.last() {
                    line.pop();
                }

                String::from_utf8(line).map_err(|_| GCloudParseError)
            }
            _ => Err(Error::ProjectIdNotFound),
        }
    }

    fn get_token(&self, _scopes: &[&str]) -> Option<Token> {
        None
    }

    async fn refresh_token(&self, _client: &HyperClient, _scopes: &[&str]) -> Result<Token, Error> {
        let mut command = Command::new(&self.gcloud);
        command.args(&["auth", "print-access-token", "--quiet"]);

        let output = match command.output() {
            Ok(output) if output.status.success() => output.stdout,
            _ => return Err(GCloudError),
        };

        let access_token = String::from_utf8(output).map_err(|_| GCloudParseError)?;
        serde_json::from_value::<Token>(json!({ "access_token": access_token.trim() }))
            .map_err(ParsingError)
    }
}
