# GCP Auth
[![Crates.io][crates-badge]][crates-url]
[![Documentation][docs-badge]][docs-url]
[![MIT licensed][mit-badge]][mit-url]

[crates-badge]: https://img.shields.io/crates/v/gcp_auth.svg
[crates-url]: https://crates.io/crates/gcp_auth
[docs-badge]: https://docs.rs/gcp_auth/badge.svg
[docs-url]: https://docs.rs/gcp_auth
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: LICENSE

GCP Auth is a simple, minimal authentication library for Google Cloud Platform (GCP)
providing authentication using services accounts. Once authenticated, the service
account can be used to acquire bearer tokens for use in authenticating against GCP
services.

The library looks for authentication methods in the following order:

1. Path to service account JSON configuration file using GOOGLE_APPLICATION_CREDENTIALS
environment variable. The service account configuration file can be downloaded in the
IAM service when displaying service account detail. The downloaded JSON file should 
be provided without any further modification.
2. Invoking the library inside GCP environment fetches the default service account
for the service and he application is authenticated using that particular account
3. Application default credentials. Local user authetincation for development purposes
created using `gcloud auth` application.
4. If none of the above can be used an error occurs

Tokens should not be cached in the application; before every use a new token should
be requested. The GCP auth library contains logic to determine if an already
available token can be used, or if a new token should be requested.

## Default service account

When running inside GCP the library can be asked without any further configuration to
provide a bearer token for the current service account of the service.

```rust
let scopes = &["https://www.googleapis.com/auth/bigquery/"];
let authentication_manager = gcp_auth::init().await?;
let token = authentication_manager.get_token(scopes).await?;
```

## Custom service account

When running outside of GCP (for example, on a developer's laptop), a custom service
account may be used to grant some permissions. To use a custom service account a
configuration file containing a private key can be downloaded in IAM service for the
service account you intend to use. The configuration file has to be available to the
application at run time. The path to the configuration file is specified by the
`GOOGLE_APPLICATION_CREDENTIALS` environment variable.

```rust
// With the GOOGLE_APPLICATION_CREDENTIALS environment variable set
let scopes = &["https://www.googleapis.com/auth/bigquery/"];
let authentication_manager = gcp_auth::init().await?;
let token = authentication_manager.get_token(&scopes).await?;
```

## Local user authentication

This authentication method allows developers to authenticate again GCP when
developing locally. Its use should be limited to development. Credentials can be
set up using the `gcloud auth` utility. Credentials are read from file `~/.config/gcloud/application_default_credentials.json`.

## FAQ

### Does the library support windows?

No.

## Getting tokens in multithreaded async programs

There is a simple pattern that can be used in async/await programs,
to avoid creating multiple instances of `AuthenticationManager`:

```rust
use once_cell::sync::Lazy;

static AUTHENTICATOR: Lazy<gcp_auth::AuthenticationManager> =
    Lazy::new(|| {
        futures::executor::block_on(gcp_auth::init()).expect("Should set-up auth")
    });
```

# License

Parts of the implementatino have been sourced from [yup-oauth2](https://github.com/dermesser/yup-oauth2).

Licensed under [MIT license](http://opensource.org/licenses/MIT).
