use crate::authentication_manager::ServiceAccount;
use crate::error::Error::{
    GCloudError, GCloudNotFound, GCloudParseError, NoProjectId, ParsingError,
};
use serde_json::json;
use std::path::PathBuf;
use std::process::Command;
use which::which;
use crate::types::HyperClient;
use crate::error::Error;
use crate::Token;
use async_trait::async_trait;

#[derive(Debug)]
pub(crate) struct GCloudAuthorizedUser {
    gcloud: PathBuf,
}

impl GCloudAuthorizedUser {
    pub(crate) async fn new() -> Result<Self, Error> {
        which("gcloud")
            .map_err(|_| GCloudNotFound)
            .map(|path| Self { gcloud: path })
    }
}

#[async_trait]
impl ServiceAccount for GCloudAuthorizedUser {
    async fn project_id(&self, _: &HyperClient) -> Result<String, Error> {
        Err(NoProjectId)
    }

    fn get_token(&self, _scopes: &[&str]) -> Option<Token> {
        None
    }

    async fn refresh_token(&self, _client: &HyperClient, _scopes: &[&str]) -> Result<Token, Error> {
        let mut command = Command::new(&self.gcloud);
        command.args(&["auth", "print-access-token", "--quiet"]);

        match command.output() {
            Ok(output) if output.status.success() => String::from_utf8(output.stdout)
                .map_err(|_| GCloudParseError)
                .and_then(|access_token| {
                    serde_json::from_value::<Token>(json!({ "access_token": access_token.trim() }))
                        .map_err(ParsingError)
                }),
            _ => Err(GCloudError),
        }
    }
}
