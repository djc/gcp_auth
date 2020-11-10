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

Library implements two authenticatiom methods:

1. Default service accounts - can be used inside GCP
2. Custom service account - provided using an environment variable
3. Local user authentication - for development purposes only, using `gcloud auth` application

Tokens should not be cached in the application; before every use a new token should
be requested. The GCP auth library contains logic to determine if an already
available token can be used, or if a new token should be requested.

## Default service account

When running inside GCP the library can be asked without any further configuration to
provide a bearer token for the current service account of the service.

```rust
let authentication_manager = gcp_auth::init().await?;
let token = authentication_manager.get_token().await?;
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
let authentication_manager = gcp_auth::init().await?;
let token = authentication_manager.get_token().await?;
```

## Local user authentication

This authentication method allows developers to authenticate again GCP when
developing locally. Its use should be limited to development. Credentials can be
set up using the `gcloud auth` utility. Credentials are read from file `~/.config/gcloud/ication_default_credentials.json`.

## FAQ

### Does the library support windows?

No.

# License

Parts of the implementatino have been sourced from [yup-oauth2](https://github.com/dermesser/yup-oauth2).

Licensed under [MIT license](http://opensource.org/licenses/MIT).
