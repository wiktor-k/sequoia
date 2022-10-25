//! Implementation of AEAD using Nettle cryptographic library.
use std::cmp::Ordering;

use nettle::{aead, cipher};

use crate::{Error, Result};

use crate::crypto::aead::{Aead, CipherOp};
use crate::crypto::mem::secure_cmp;
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

/// Disables authentication checks.
///
/// This is DANGEROUS, and is only useful for debugging problems with
/// malformed AEAD-encrypted messages.
const DANGER_DISABLE_AUTHENTICATION: bool = false;

impl<T: nettle::aead::Aead> seal::Sealed for T {}
impl<T: nettle::aead::Aead> Aead for T {
    fn update(&mut self, ad: &[u8]) -> Result<()> {
        self.update(ad);
        Ok(())
    }
    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        self.encrypt(dst, src);
        Ok(())
    }
    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8], valid_digest: &[u8]) -> Result<()> {
        self.decrypt(dst, src);
        let mut digest = vec![0u8; self.digest_size()];

        self.digest(&mut digest);
        if secure_cmp(&digest[..], valid_digest)
             != Ordering::Equal && ! DANGER_DISABLE_AUTHENTICATION
            {
                 return Err(Error::ManipulatedMessage.into());
            }
        Ok(())
    }
    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        self.digest(digest);
        Ok(())
    }
    fn digest_size(&self) -> usize {
        self.digest_size()
    }
}

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        nonce: &[u8],
        _op: CipherOp,
    ) -> Result<Box<dyn Aead>> {
        match self {
            AEADAlgorithm::EAX => match sym_algo {
                SymmetricAlgorithm::AES128 => Ok(Box::new(
                    aead::Eax::<cipher::Aes128>::with_key_and_nonce(key, nonce)?,
                )),
                SymmetricAlgorithm::AES192 => Ok(Box::new(
                    aead::Eax::<cipher::Aes192>::with_key_and_nonce(key, nonce)?,
                )),
                SymmetricAlgorithm::AES256 => Ok(Box::new(
                    aead::Eax::<cipher::Aes256>::with_key_and_nonce(key, nonce)?,
                )),
                SymmetricAlgorithm::Twofish => Ok(Box::new(
                    aead::Eax::<cipher::Twofish>::with_key_and_nonce(key, nonce)?,
                )),
                SymmetricAlgorithm::Camellia128 => Ok(Box::new(
                    aead::Eax::<cipher::Camellia128>::with_key_and_nonce(key, nonce)?,
                )),
                SymmetricAlgorithm::Camellia192 => Ok(Box::new(
                    aead::Eax::<cipher::Camellia192>::with_key_and_nonce(key, nonce)?,
                )),
                SymmetricAlgorithm::Camellia256 => Ok(Box::new(
                    aead::Eax::<cipher::Camellia256>::with_key_and_nonce(key, nonce)?,
                )),
                _ => Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },
            _ => Err(Error::UnsupportedAEADAlgorithm(*self).into()),
        }
    }
}
