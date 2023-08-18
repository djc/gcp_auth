use std::path::{Path, PathBuf};

use serde::Deserialize;
use tokio::fs;

use crate::{
    authentication_manager::ServiceAccount,
    custom_service_account::ApplicationCredentials,
    default_authorized_user::{ConfigDefaultCredentials, UserCredentials},
    service_account_impersonation::ImpersonatedServiceAccount,
    types::HyperClient,
    CustomServiceAccount, Error,
};

// Implementation referenced from
// https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/google.go#L158
// Currently not implementing external account credentials
// Currently not implementing impersonating service accounts (coming soon !)
#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum FlexibleCredentialSource {
    // This credential parses the `key.json` file created when running
    // `gcloud iam service-accounts keys create key.json --iam-account=SA_NAME@PROJECT_ID.iam.gserviceaccount.com`
    ServiceAccount(ApplicationCredentials),
    // This credential parses the `~/.config/gcloud/application_default_credentials.json` file
    // created when running `gcloud auth application-default login`
    AuthorizedUser(UserCredentials),
    // This credential parses the `~/.config/gcloud/application_default_credentials.json` file
    // created when running `gcloud auth application-default login --impersonate-service-account <service account>`
    ImpersonatedServiceAccount(ImpersonatedServiceAccountCredentials),
}

impl FlexibleCredentialSource {
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

    pub(crate) async fn from_default_credentials() -> Result<Self, Error> {
        tracing::debug!("Loading user credentials file");
        let mut home = dirs_next::home_dir().ok_or(Error::NoHomeDir)?;
        home.push(Self::USER_CREDENTIALS_PATH);
        Self::from_file(home).await
    }

    pub(crate) async fn try_into_service_account(
        self,
        client: &HyperClient,
    ) -> Result<Box<dyn ServiceAccount>, Error> {
        match self {
            FlexibleCredentialSource::ServiceAccount(creds) => {
                let service_account = CustomServiceAccount::new(creds)?;
                Ok(Box::new(service_account))
            }
            FlexibleCredentialSource::AuthorizedUser(creds) => {
                let service_account =
                    ConfigDefaultCredentials::from_user_credentials(creds, client).await?;
                Ok(Box::new(service_account))
            }
            FlexibleCredentialSource::ImpersonatedServiceAccount(creds) => {
                let source_creds: Box<dyn ServiceAccount> = match *creds.source_credentials {
                    FlexibleCredentialSource::AuthorizedUser(creds) => {
                        let service_account =
                            ConfigDefaultCredentials::from_user_credentials(creds, client).await?;
                        Box::new(service_account)
                    }
                    FlexibleCredentialSource::ServiceAccount(creds) => {
                        let service_account = CustomServiceAccount::new(creds)?;
                        Box::new(service_account)
                    }
                    FlexibleCredentialSource::ImpersonatedServiceAccount(_) => {
                        return Err(Error::NestedImpersonation)
                    }
                };

                let service_account = ImpersonatedServiceAccount::new(
                    source_creds,
                    creds.service_account_impersonation_url,
                    creds.delegates,
                );

                Ok(Box::new(service_account))
            }
        }
    }

    /// Read service account credentials from the given JSON file
    async fn from_file<T: AsRef<Path>>(path: T) -> Result<Self, Error> {
        let creds_string = fs::read_to_string(&path)
            .await
            .map_err(Error::UserProfilePath)?;

        serde_json::from_str::<FlexibleCredentialSource>(&creds_string)
            .map_err(Error::CustomServiceAccountCredentials)
    }
}

// This credential uses the `source_credentials` to get a token
// and then uses that token to get a token impersonating the service
// account specified by `service_account_impersonation_url`.
// refresh logic https://github.com/golang/oauth2/blob/a835fc4358f6852f50c4c5c33fddcd1adade5b0a/google/internal/externalaccount/impersonate.go#L57
#[derive(Deserialize, Debug)]
pub(crate) struct ImpersonatedServiceAccountCredentials {
    service_account_impersonation_url: String,
    source_credentials: Box<FlexibleCredentialSource>,
    delegates: Vec<String>,
}

#[cfg(test)]
mod tests {
    use crate::{flexible_credential_source::FlexibleCredentialSource, types};

    #[tokio::test]
    async fn test_parse_application_default_credentials() {
        let test_creds = r#"{
            "client_id": "***id***.apps.googleusercontent.com",
            "client_secret": "***secret***",
            "quota_project_id": "test_project",
            "refresh_token": "***refresh***",
            "type": "authorized_user"
        }"#;

        let cred_source: FlexibleCredentialSource =
            serde_json::from_str(test_creds).expect("Valid creds to parse");

        assert!(matches!(
            cred_source,
            FlexibleCredentialSource::AuthorizedUser(_)
        ));

        // Can't test converting this into a service account because it requires actually getting a key
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

        let cred_source: FlexibleCredentialSource =
            serde_json::from_str(test_creds).expect("Valid creds to parse");

        assert!(matches!(
            cred_source,
            FlexibleCredentialSource::ServiceAccount(_)
        ));

        let client = types::client();
        let creds = cred_source
            .try_into_service_account(&client)
            .await
            .expect("Valid creds to parse");

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

        let k2 = r#"{
            "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
            "client_email": "gopher@developer.gserviceaccount.com",
            "client_id": "gopher.apps.googleusercontent.com",
            "type": "service_account"
        }"#;

        let k3 = r#"{
            "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
            "client_email": "gopher@developer.gserviceaccount.com",
            "client_id": "gopher.apps.googleusercontent.com",
            "token_uri": "https://accounts.google.com/o/gophers/token",
            "type": "service_account"
        }"#;

        let client = types::client();
        for key in [k1, k2, k3] {
            let cred_source: FlexibleCredentialSource =
                serde_json::from_str(key).expect("Valid creds to parse");

            assert!(matches!(
                cred_source,
                FlexibleCredentialSource::ServiceAccount(_)
            ));

            let creds = cred_source
                .try_into_service_account(&client)
                .await
                .expect("Valid creds to parse");

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
        }
    }

    #[tokio::test]
    async fn test_parse_impersonating_service_account() {
        let impersonate_from_user_creds = r#"{
            "delegates": [],
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test_account@test_project.iam.gserviceaccount.com:generateAccessToken",
            "source_credentials": {
                "client_id": "***id***.apps.googleusercontent.com",
                "client_secret": "***secret***",
                "refresh_token": "***refresh***",
                "type": "authorized_user",
                "quota_project_id": "test_project"
            },
            "type": "impersonated_service_account"
        }"#;

        let cred_source: FlexibleCredentialSource =
            serde_json::from_str(impersonate_from_user_creds).expect("Valid creds to parse");

        assert!(matches!(
            cred_source,
            FlexibleCredentialSource::ImpersonatedServiceAccount(_)
        ));

        let impersonate_from_service_key = r#"{
            "delegates": [],
            "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test_account@test_project.iam.gserviceaccount.com:generateAccessToken",
            "source_credentials": {
                "private_key_id": "268f54e43a1af97cfc71731688434f45aca15c8b",
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5M5y3WwsRk8NX\npF9fKaZukNspot9Ecmk1PAkupcHLKVhalwPxU4sMNWXgM9H2LTWSvvyOT//rDQpn\n3SGYri/lMhzb4lI8h10E7k6zyFQUPujxkXFBkMOzhIDUgtiiht0WvIw6M8nbaPqI\nxn/aYmPsFhvJfKCthYAt2UUz+D3enI9QjCuhic8iSMnvKT8m0QkOG2eALYGUaLF1\ngRkbV4BiBUGZfXfNEBdux3Wf4kNUau32LA0XotomlvNvf1oH77v5Hc1R/KMMIk5F\nJWVBuAr4jwkN9hwtOozpJ/52wSpddxsZuj+0nP1a3f0UyvrmMnuwszardPK39BoH\nJ+5+HZM3AgMBAAECggEADrHZrXK73hkrVrjkGFjlq8Ayo4sYzAWH84Ff+SONzODq\n8cUpuuw2DDHwc2mpLy9HIO2mfGQ8mhneyX7yO3sWscjYIVpDzCmxZ8LA2+L5SOH0\n+bXglqM14/iPgE0hg0PQJw2u0q9pRM9/kXquilVkOEdIzSPmW95L3Vdv9j+sKQ2A\nOL23l4dsaG4+i1lWRBKiGsLh1kB9FRnm4BzcOxd3WGooy7L1/jo9BoYRss1YABls\nmmyZ9f7r28zjclhpOBkE3OXX0zNbp4yIu1O1Bt9X2p87EOuYqlFA5eEvDbiTPZbk\n6wKEX3BPUkeIo8OaGvsGhHCWx0lv/sDPw/UofycOgQKBgQD4BD059aXEV13Byc5D\nh8LQSejjeM/Vx+YeCFI66biaIOvUs+unyxkH+qxXTuW6AgOgcvrJo93xkyAZ9SeR\nc6Vj9g5mZ5vqSJz5Hg8h8iZBAYtf40qWq0pHcmUIm2Z9LvrG5ZFHU5EEcCtLyBVS\nAv+pLLLf3OsAkJuuqTAgygBbOwKBgQC/KcBa9sUg2u9qIpq020UOW/n4KFWhSJ8h\ngXqqmjOnPqmDc5AnYg1ZdYdqSSgdiK8lJpRL/S2UjYUQp3H+56z0eK/b1iKM51n+\n6D80nIxWeKJ+n7VKI7cBXwc/KokaXgkz0It2UEZSlhPUMImnYcOvGIZ7cMr3Q6mf\n6FwD15UQNQKBgQDyAsDz454DvvS/+noJL1qMAPL9tI+pncwQljIXRqVZ0LIO9hoH\nu4kLXjH5aAWGwhxj3o6VYA9cgSIb8jrQFbbXmexnRMbBkGWMOSavCykE2cr0oEfS\nSgbLPPcVtP4HPWZ72tsubH7fg8zbv7v+MOrkW7eX9mxiOrmPb4yFElfSrQKBgA7y\nMLvr91WuSHG/6uChFDEfN9gTLz7A8tAn03NrQwace5xveKHbpLeN3NyOg7hra2Y4\nMfgO/3VR60l2Dg+kBX3HwdgqUeE6ZWrstaRjaQWJwQqtafs196T/zQ0/QiDxoT6P\n25eQhy8F1N8OPHT9y9Lw0/LqyrOycpyyCh+yx1DRAoGAJ/6dlhyQnwSfMAe3mfRC\noiBQG6FkyoeXHHYcoQ/0cSzwp0BwBlar1Z28P7KTGcUNqV+YfK9nF47eoLaTLCmG\nG5du0Ds6m2Eg0sOBBqXHnw6R1PC878tgT/XokNxIsVlF5qRz88q7Rn0J1lzB7+Tl\n2HSAcyIUcmr0gxlhRmC2Jq4=\n-----END PRIVATE KEY-----\n",
                "client_email": "gopher@developer.gserviceaccount.com",
                "client_id": "gopher.apps.googleusercontent.com",
                "token_uri": "https://accounts.google.com/o/gophers/token",
                "type": "service_account",
                "audience": "https://testservice.googleapis.com/",
                "project_id": "test_project"
            },
            "type": "impersonated_service_account"
        }"#;

        let cred_source: FlexibleCredentialSource =
            serde_json::from_str(impersonate_from_service_key).expect("Valid creds to parse");

        assert!(matches!(
            cred_source,
            FlexibleCredentialSource::ImpersonatedServiceAccount(_)
        ));

        let client = types::client();
        let creds = cred_source
            .try_into_service_account(&client)
            .await
            .expect("Valid creds to parse");

        assert_eq!(
            creds
                .project_id(&client)
                .await
                .expect("Project ID to be present"),
            "test_project".to_string(),
            "Project ID should be parsed"
        );
    }
}
