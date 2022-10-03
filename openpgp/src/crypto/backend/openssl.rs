//! Implementation of Sequoia crypto API using the OpenSSL cryptographic library.

use crate::types::*;

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

/// Returns a short, human-readable description of the backend.
pub fn backend() -> String {
    "OpenSSL".to_string()
}

/// Fills the given buffer with random data.
pub fn random(buf: &mut [u8]) {
    // random is expected to always work or panic on wrong data.
    // This is similar to what other backends do like CNG or Rust
    // see: https://docs.rs/rand/latest/rand/trait.RngCore.html#tymethod.fill_bytes
    openssl::rand::rand_bytes(buf).expect("rand_bytes to work");
}

impl PublicKeyAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self {
            RSAEncryptSign | RSAEncrypt | RSASign => true,
            ECDH | ECDSA | EdDSA => true,
            _ => false,
        }
    }
}

impl Curve {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use Curve::*;
        match self {
            NistP256 | NistP384 | NistP521 => true,
            Ed25519 | Cv25519 => true,
            _ => false,
        }
    }
}

impl AEADAlgorithm {
    /// Returns the best AEAD mode supported by the backend.
    ///
    /// This SHOULD return OCB, which is the mandatory-to-implement
    /// algorithm and the most performing one, but fall back to any
    /// supported algorithm.
    pub(crate) const fn const_default() -> AEADAlgorithm {
        AEADAlgorithm::OCB
    }

    pub(crate) fn is_supported_by_backend(&self) -> bool {
        *self == AEADAlgorithm::OCB
    }
}
