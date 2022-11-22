use crate::crypto::hash::Digest;
use crate::types::HashAlgorithm;
use crate::Result;

use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;

#[derive(Clone)]
struct OpenSslDigest {
    digest_size: usize,
    algo: HashAlgorithm,
    hasher: Hasher,
    update_result: std::result::Result<(), ErrorStack>,
}

impl OpenSslDigest {
    fn new(algo: HashAlgorithm) -> Result<Self> {
        if let Some(md) = get_md(algo) {
            Ok(Self {
                digest_size: md.size(),
                algo,
                update_result: Ok(()),
                hasher: Hasher::new(md)?,
            })
        } else {
            Err(crate::Error::UnsupportedHashAlgorithm(algo).into())
        }
    }
}

impl Digest for OpenSslDigest {
    fn algo(&self) -> HashAlgorithm {
        self.algo
    }

    fn digest_size(&self) -> usize {
        self.digest_size
    }

    fn update(&mut self, data: &[u8]) {
        if self.update_result.is_err() {
            return;
        }
        self.update_result = self.hasher.update(data);
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        self.update_result.clone()?;
        let result = self.hasher.finish()?;
        digest.copy_from_slice(&result[..digest.len()]);
        Ok(())
    }
}

impl std::io::Write for OpenSslDigest {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        // Do nothing.
        Ok(())
    }
}

fn get_md(algo: HashAlgorithm) -> Option<MessageDigest> {
    use HashAlgorithm::*;
    let nid = match algo {
        MD5 => Nid::MD5,
        RipeMD => Nid::RIPEMD160,
        SHA1 => Nid::SHA1,
        SHA256 => Nid::SHA256,
        SHA384 => Nid::SHA384,
        SHA512 => Nid::SHA512,
        SHA224 => Nid::SHA224,
        _ => return None,
    };
    MessageDigest::from_nid(nid)
}

impl HashAlgorithm {
    /// Whether Sequoia supports this algorithm.
    pub fn is_supported(self) -> bool {
        get_md(self).is_some()
    }

    /// Creates a new hash context for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with `Error::UnsupportedHashAlgorithm` if Sequoia does
    /// not support this algorithm. See
    /// [`HashAlgorithm::is_supported`].
    ///
    ///   [`HashAlgorithm::is_supported`]: HashAlgorithm::is_supported()
    pub(crate) fn new_hasher(self) -> Result<Box<dyn Digest>> {
        Ok(Box::new(OpenSslDigest::new(self)?))
    }
}
