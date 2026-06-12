//! RSA PKCS1 SHA256 signing, abstracted over the selected crypto provider.
//!
//! The backing implementation is chosen at compile time by the enabled
//! feature: `ring` (the default) or `aws-lc-rs`. `ring` takes precedence when
//! both are enabled. Building with neither is a hard error, since signing JWTs
//! for custom service accounts is not possible without a provider.

use std::fmt;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::PrivatePkcs8KeyDer;

use crate::Error;

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!(
    "gcp_auth requires a crypto provider: enable either the `ring` (default) or `aws-lc-rs` feature"
);

#[cfg(feature = "ring")]
use ring::rand::SystemRandom;
#[cfg(feature = "ring")]
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
use aws_lc_rs::rand::SystemRandom;
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
use aws_lc_rs::signature::{KeyPair, RsaKeyPair, RSA_PKCS1_SHA256};

/// An RSA PKCS1 SHA256 signer
pub struct Signer {
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl Signer {
    pub(crate) fn new(pem_pkcs8: &str) -> Result<Self, Error> {
        let key = match PrivatePkcs8KeyDer::from_pem_slice(pem_pkcs8.as_bytes()) {
            Ok(key) => key,
            Err(err) => {
                return Err(Error::Other(
                    "failed to parse PKCS#8 RSA key pair",
                    err.into(),
                ))
            }
        };

        Ok(Signer {
            key: RsaKeyPair::from_pkcs8(key.secret_pkcs8_der())
                .map_err(|_| Error::Str("invalid private key in credentials"))?,
            rng: SystemRandom::new(),
        })
    }

    /// Sign the input message and return the signature
    pub fn sign(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        #[cfg(feature = "ring")]
        let modulus_len = self.key.public().modulus_len();
        #[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
        let modulus_len = self.key.public_key().modulus_len();

        let mut signature = vec![0; modulus_len];
        self.key
            .sign(&RSA_PKCS1_SHA256, &self.rng, input, &mut signature)
            .map_err(|_| Error::Str("failed to sign with credentials key"))?;
        Ok(signature)
    }
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer").finish()
    }
}
