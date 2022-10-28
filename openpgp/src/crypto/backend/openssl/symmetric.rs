use crate::crypto::symmetric::Mode;

use crate::types::SymmetricAlgorithm;
use crate::{Error, Result};

use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;

struct OpenSslMode {
    ctx: CipherCtx,
    block_size: usize,
}

impl OpenSslMode {
    fn new(ctx: CipherCtx, block_size: usize) -> Self {
        Self { ctx, block_size }
    }
}

impl Mode for OpenSslMode {
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        let mut dst_vec = vec![];
        self.ctx.cipher_update_vec(src, &mut dst_vec)?;
        self.ctx.cipher_final_vec(&mut dst_vec)?;
        dst.copy_from_slice(&dst_vec[..dst.len()]);
        Ok(())
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        self.encrypt(dst, src)
    }
}

impl SymmetricAlgorithm {
    /// Returns whether this algorithm is supported by the crypto backend.
    ///
    /// All backends support all the AES variants.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::SymmetricAlgorithm;
    ///
    /// assert!(SymmetricAlgorithm::AES256.is_supported());
    ///
    /// assert!(!SymmetricAlgorithm::TripleDES.is_supported());
    /// assert!(!SymmetricAlgorithm::IDEA.is_supported());
    /// assert!(!SymmetricAlgorithm::Unencrypted.is_supported());
    /// assert!(!SymmetricAlgorithm::Private(101).is_supported());
    /// ```
    pub fn is_supported(&self) -> bool {
        use SymmetricAlgorithm::*;
        match self {
            AES128 | AES192 | AES256 => true,
            Camellia128 => true,
            _ => false,
        }
    }

    /// Length of a key for this algorithm in bytes.
    ///
    /// Fails if Sequoia does not support this algorithm.
    pub fn key_size(self) -> Result<usize> {
        Ok(match self {
            SymmetricAlgorithm::AES128 => 16,
            SymmetricAlgorithm::AES192 => 24,
            SymmetricAlgorithm::AES256 => 32,
            SymmetricAlgorithm::Camellia128 => 16,
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        })
    }

    /// Length of a block for this algorithm in bytes.
    ///
    /// Fails if Sequoia does not support this algorithm.
    pub fn block_size(self) -> Result<usize> {
        Ok(match self {
            SymmetricAlgorithm::AES128 => 16,
            SymmetricAlgorithm::AES192 => 16,
            SymmetricAlgorithm::AES256 => 16,
            SymmetricAlgorithm::Camellia128 => 16,
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        })
    }

    /// Creates a OpenSSL context for encrypting in CFB mode.
    pub(crate) fn make_encrypt_cfb(self, key: &[u8], iv: Vec<u8>) -> Result<Box<dyn Mode>> {
        let cipher = match self {
            SymmetricAlgorithm::AES128 => Cipher::aes_128_cfb128(),
            SymmetricAlgorithm::AES192 => Cipher::aes_192_cfb128(),
            SymmetricAlgorithm::AES256 => Cipher::aes_256_cfb128(),
            SymmetricAlgorithm::Camellia128 => Cipher::camellia128_cfb128(),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        };
        let mut ctx = CipherCtx::new()?;
        ctx.encrypt_init(Some(cipher), Some(key), Some(&iv))?;
        Ok(Box::new(OpenSslMode::new(ctx, cipher.block_size())))
    }

    /// Creates a OpenSSL context for decrypting in CFB mode.
    pub(crate) fn make_decrypt_cfb(self, key: &[u8], iv: Vec<u8>) -> Result<Box<dyn Mode>> {
        let cipher = match self {
            SymmetricAlgorithm::AES128 => Cipher::aes_128_cfb128(),
            SymmetricAlgorithm::AES192 => Cipher::aes_192_cfb128(),
            SymmetricAlgorithm::AES256 => Cipher::aes_256_cfb128(),
            SymmetricAlgorithm::Camellia128 => Cipher::camellia128_cfb128(),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        };
        let mut ctx = CipherCtx::new()?;
        ctx.decrypt_init(Some(cipher), Some(key), Some(&iv))?;
        Ok(Box::new(OpenSslMode::new(ctx, cipher.block_size())))
    }

    /// Creates a OpenSSL context for encrypting in ECB mode.
    pub(crate) fn make_encrypt_ecb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        let cipher = match self {
            SymmetricAlgorithm::AES128 => Cipher::aes_128_ecb(),
            SymmetricAlgorithm::AES192 => Cipher::aes_192_ecb(),
            SymmetricAlgorithm::AES256 => Cipher::aes_256_ecb(),
            SymmetricAlgorithm::Camellia128 => Cipher::camellia128_ecb(),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        };
        let mut ctx = CipherCtx::new()?;
        ctx.encrypt_init(Some(cipher), Some(key), None)?;
        Ok(Box::new(OpenSslMode::new(ctx, cipher.block_size())))
    }

    /// Creates a OpenSSL context for decrypting in ECB mode.
    pub(crate) fn make_decrypt_ecb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        let cipher = match self {
            SymmetricAlgorithm::AES128 => Cipher::aes_128_ecb(),
            SymmetricAlgorithm::AES192 => Cipher::aes_192_ecb(),
            SymmetricAlgorithm::AES256 => Cipher::aes_256_ecb(),
            SymmetricAlgorithm::Camellia128 => Cipher::camellia128_ecb(),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        };
        let mut ctx = CipherCtx::new()?;
        ctx.decrypt_init(Some(cipher), Some(key), None)?;
        ctx.set_padding(false);
        Ok(Box::new(OpenSslMode::new(ctx, cipher.block_size())))
    }
}
