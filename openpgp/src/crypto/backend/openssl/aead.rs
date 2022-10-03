//! Implementation of AEAD using OpenSSL cryptographic library.

use crate::{Error, Result};

use crate::crypto::aead::{Aead, CipherOp};
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

use openssl::symm::{Cipher, Crypter, Mode};

struct OpenSslContextEncrypt {
    crypter: Crypter,
    finalized: bool,
}

impl Aead for OpenSslContextEncrypt {
    fn update(&mut self, ad: &[u8]) -> Result<()> {
        self.crypter.aad_update(ad)?;
        Ok(())
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        let mut target = vec![0; src.len() + 16];

        let size = self.crypter.update(src, &mut target)?;
        dst.get_mut(..size).ok_or(Error::IndexOutOfRange)?.copy_from_slice(&target[..size]);

        let final_size = self.crypter.finalize(&mut target)?;
        self.finalized = true;
        dst.get_mut(size..(size + final_size)).ok_or(Error::IndexOutOfRange)?
            .copy_from_slice(&target[..final_size]);
        Ok(())
    }

    fn decrypt_verify(&mut self, _dst: &mut [u8], _src: &[u8], _valid_digest: &[u8]) -> Result<()> {
        panic!("Decrypt called in encrypt context");
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        if ! self.finalized {
            assert_eq!(0, self.crypter.finalize(&mut [0; 16])?);
        }
        self.crypter.get_tag(digest)?;
        Ok(())
    }

    fn digest_size(&self) -> usize {
        panic!("Unsupported op");
    }
}

impl crate::seal::Sealed for OpenSslContextEncrypt {}

struct OpenSslContextDecrypt {
    crypter: Crypter,
}

impl Aead for OpenSslContextDecrypt {
    fn update(&mut self, ad: &[u8]) -> Result<()> {
        self.crypter.aad_update(ad)?;
        Ok(())
    }

    fn encrypt(&mut self, _dst: &mut [u8], _src: &[u8]) -> Result<()> {
        panic!("Encrypt called in decrypt context");
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8], valid_digest: &[u8]) -> Result<()> {
        let mut target = vec![0; src.len() + 16];
        let size = self.crypter.update(src, &mut target)?;
        dst.get_mut(..size).ok_or(Error::IndexOutOfRange)?.copy_from_slice(&target[..size]);

        self.crypter.set_tag(valid_digest)?;
        let final_size = self.crypter.finalize(&mut target)?;
        dst.get_mut(size..(size + final_size)).ok_or(Error::IndexOutOfRange)?
            .copy_from_slice(&target[..final_size]);

        Ok(())
    }

    fn digest(&mut self, _digest: &mut [u8]) -> Result<()> {
        panic!("Unsupported op, use decrypt_verify");
    }

    fn digest_size(&self) -> usize {
        panic!("Unsupported operation");
    }
}

impl crate::seal::Sealed for OpenSslContextDecrypt {}

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        nonce: &[u8],
        op: CipherOp,
    ) -> Result<Box<dyn Aead>> {
        match self {
            AEADAlgorithm::OCB => {
                let cipher = match sym_algo {
                    SymmetricAlgorithm::AES128 => Cipher::aes_128_ocb(),
                    SymmetricAlgorithm::AES192 => Cipher::aes_192_ocb(),
                    SymmetricAlgorithm::AES256 => Cipher::aes_256_ocb(),
                    _ => return Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
                };
                let crypter = Crypter::new(
                    cipher,
                    match op {
                        CipherOp::Encrypt => Mode::Encrypt,
                        CipherOp::Decrypt => Mode::Decrypt,
                    },
                    key,
                    Some(nonce),
                )?;
                match op {
                    CipherOp::Decrypt => Ok(Box::new(OpenSslContextDecrypt { crypter })),
                    CipherOp::Encrypt => Ok(Box::new(OpenSslContextEncrypt { crypter, finalized: false })),
                }
            }
            _ => Err(Error::UnsupportedAEADAlgorithm(*self).into()),
        }
    }
}
