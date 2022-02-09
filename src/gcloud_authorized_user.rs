use std::path::{Path, PathBuf};
use std::process::Command;

use async_trait::async_trait;
use which::which;

use crate::authentication_manager::ServiceAccount;
use crate::error::Error;
use crate::error::Error::{GCloudError, GCloudNotFound, GCloudParseError};
use crate::types::HyperClient;
use crate::Token;

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
        run(&self.gcloud, &["config", "get-value", "project"])
    }

    fn get_token(&self, _scopes: &[&str]) -> Option<Token> {
        None
    }

    async fn refresh_token(&self, _client: &HyperClient, _scopes: &[&str]) -> Result<Token, Error> {
        Ok(Token::from_string(run(
            &self.gcloud,
            &["auth", "print-access-token", "--quiet"],
        )?))
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
