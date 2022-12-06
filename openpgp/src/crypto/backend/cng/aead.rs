//! Implementation of AEAD using Windows CNG API.
use std::cmp::Ordering;

use crate::{Error, Result};
use crate::crypto::aead::{Aead, CipherOp};
use crate::crypto::mem::secure_cmp;
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

use eax::online::{EaxOnline, Encrypt, Decrypt};
use win_crypto_ng::symmetric::{BlockCipherKey, Aes};
use win_crypto_ng::symmetric::block_cipher::generic_array::{GenericArray, ArrayLength};
use win_crypto_ng::symmetric::block_cipher::generic_array::typenum::{U128, U192, U256};

/// Disables authentication checks.
///
/// This is DANGEROUS, and is only useful for debugging problems with
/// malformed AEAD-encrypted messages.
const DANGER_DISABLE_AUTHENTICATION: bool = false;

trait GenericArrayExt<T, N: ArrayLength<T>> {
    const LEN: usize;

    /// Like [`GenericArray::from_slice`], but fallible.
    fn try_from_slice(slice: &[T]) -> Result<&GenericArray<T, N>> {
        if slice.len() == Self::LEN {
            Ok(GenericArray::from_slice(slice))
        } else {
            Err(Error::InvalidArgument(
                format!("Invalid slice length, want {}, got {}",
                        Self::LEN, slice.len())).into())
        }
    }
}

impl<T, N: ArrayLength<T>> GenericArrayExt<T, N> for GenericArray<T, N> {
    const LEN: usize = N::USIZE;
}

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        nonce: &[u8],
        op: CipherOp,
    ) -> Result<Box<dyn Aead>> {

        match self {
            AEADAlgorithm::EAX => match sym_algo {
                | SymmetricAlgorithm::AES128 => {
                    let key = GenericArray::try_from_slice(key)?;
                    let nonce = GenericArray::try_from_slice(nonce)?;
                    Ok(match op {
                        CipherOp::Encrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U128>, Encrypt>::with_key_and_nonce(key, nonce)),
                        CipherOp::Decrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U128>, Decrypt>::with_key_and_nonce(key, nonce)),
                    })
                }
                SymmetricAlgorithm::AES192 => {
                    let key = GenericArray::try_from_slice(key)?;
                    let nonce = GenericArray::try_from_slice(nonce)?;
                    Ok(match op {
                        CipherOp::Encrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U192>, Encrypt>::with_key_and_nonce(key, nonce)),
                        CipherOp::Decrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U192>, Decrypt>::with_key_and_nonce(key, nonce)),
                    })
                }
                SymmetricAlgorithm::AES256 => {
                    let key = GenericArray::try_from_slice(key)?;
                    let nonce = GenericArray::try_from_slice(nonce)?;
                    Ok(match op {
                        CipherOp::Encrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U256>, Encrypt>::with_key_and_nonce(key, nonce)),
                        CipherOp::Decrypt =>
                            Box::new(EaxOnline::<BlockCipherKey<Aes, U256>, Decrypt>::with_key_and_nonce(key, nonce)),
                    })
                }
                _ => Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },
            _ => Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }
}

macro_rules! impl_aead {
    ($($type: ty),*) => {
        $(
        impl Aead for EaxOnline<$type, Encrypt> {
            fn update(&mut self, ad: &[u8]) -> Result<()> {
                self.update_assoc(ad);
                Ok(())
            }
            fn digest_size(&self) -> usize {
                <eax::Tag as GenericArrayExt<_, _>>::LEN
            }
            fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
                let tag = self.tag_clone();
                digest[..tag.len()].copy_from_slice(&tag[..]);
                Ok(())
            }
            fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
                let len = core::cmp::min(dst.len(), src.len());
                dst[..len].copy_from_slice(&src[..len]);
                EaxOnline::<$type, Encrypt>::encrypt(self, &mut dst[..len]);
                Ok(())
            }
            fn decrypt_verify(&mut self, _dst: &mut [u8], _src: &[u8], _digest: &[u8]) -> Result<()> {
                panic!("AEAD decryption called in the encryption context")
            }
        }
        impl seal::Sealed for EaxOnline<$type, Encrypt> {}
        )*
        $(
        impl Aead for EaxOnline<$type, Decrypt> {
            fn update(&mut self, ad: &[u8]) -> Result<()> {
                self.update_assoc(ad);
                Ok(())
            }
            fn digest_size(&self) -> usize {
                <eax::Tag as GenericArrayExt<_, _>>::LEN
            }
            fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
                let tag = self.tag_clone();
                digest[..tag.len()].copy_from_slice(&tag[..]);
                Ok(())
            }
            fn encrypt(&mut self, _dst: &mut [u8], _src: &[u8]) -> Result<()> {
                panic!("AEAD encryption called in the decryption context")
            }
            fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8], digest: &[u8]) -> Result<()> {
                let len = core::cmp::min(dst.len(), src.len());
                dst[..len].copy_from_slice(&src[..len]);
                self.decrypt_unauthenticated_hazmat(&mut dst[..len]);
                let mut chunk_digest = vec![0u8; self.digest_size()];

                self.digest(&mut chunk_digest)?;
                if secure_cmp(&chunk_digest[..], digest)
                    != Ordering::Equal && ! DANGER_DISABLE_AUTHENTICATION
                {
                    return Err(Error::ManipulatedMessage.into());
                }
                Ok(())
            }
        }
        impl seal::Sealed for EaxOnline<$type, Decrypt> {}
        )*
    };
}

impl_aead!(BlockCipherKey<Aes, U128>, BlockCipherKey<Aes, U192>, BlockCipherKey<Aes, U256>);
