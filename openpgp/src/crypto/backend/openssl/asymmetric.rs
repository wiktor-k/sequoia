use crate::Result;

use crate::crypto::asymmetric::{Decryptor, KeyPair, Signer};
use crate::crypto::mpi;
use crate::crypto::mpi::{ProtectedMPI, MPI};
use crate::crypto::mem::Protected;
use crate::crypto::SessionKey;
use crate::packet::key::{Key4, SecretParts};
use crate::packet::{key, Key};
use crate::types::SymmetricAlgorithm;
use crate::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};
use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;

use openssl::bn::{BigNum, BigNumRef, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey_ctx::PkeyCtx;
use openssl::rsa::{Padding, Rsa, RsaPrivateKeyBuilder};
use openssl::sign::Signer as OpenSslSigner;
use openssl::sign::Verifier;

impl TryFrom<&ProtectedMPI> for BigNum {
    type Error = anyhow::Error;
    fn try_from(mpi: &ProtectedMPI) -> std::result::Result<BigNum, anyhow::Error> {
        let mut bn = BigNum::new_secure()?;
        bn.copy_from_slice(mpi.value())?;
        Ok(bn)
    }
}

impl From<&BigNumRef> for ProtectedMPI {
    fn from(bn: &BigNumRef) -> Self {
        bn.to_vec().into()
    }
}

impl From<BigNum> for ProtectedMPI {
    fn from(bn: BigNum) -> Self {
        bn.to_vec().into()
    }
}

impl From<BigNum> for MPI {
    fn from(bn: BigNum) -> Self {
        bn.to_vec().into()
    }
}

impl TryFrom<&MPI> for BigNum {
    type Error = anyhow::Error;
    fn try_from(mpi: &MPI) -> std::result::Result<BigNum, anyhow::Error> {
        Ok(BigNum::from_slice(mpi.value())?)
    }
}

impl From<&BigNumRef> for MPI {
    fn from(bn: &BigNumRef) -> Self {
        bn.to_vec().into()
    }
}

impl TryFrom<&Curve> for Nid {
    type Error = crate::Error;
    fn try_from(curve: &Curve) -> std::result::Result<Nid, crate::Error> {
        Ok(match curve {
            Curve::NistP256 => Nid::X9_62_PRIME256V1,
            Curve::NistP384 => Nid::SECP384R1,
            Curve::NistP521 => Nid::SECP521R1,
            Curve::BrainpoolP256 => Nid::BRAINPOOL_P256R1,
            Curve::BrainpoolP512 => Nid::BRAINPOOL_P512R1,
            _ => return Err(crate::Error::UnsupportedEllipticCurve(curve.clone()).into()),
        })
    }
}

impl Signer for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        KeyPair::public(self)
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8]) -> Result<mpi::Signature> {
        use crate::PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        self.secret().map(
            |secret| match (self.public().pk_algo(), self.public().mpis(), secret) {
                (
                    RSAEncryptSign,
                    mpi::PublicKey::RSA { e, n },
                    mpi::SecretKeyMaterial::RSA { p, q, d, .. },
                )
                | (
                    RSASign,
                    mpi::PublicKey::RSA { e, n },
                    mpi::SecretKeyMaterial::RSA { p, q, d, .. },
                ) => {
                    let key =
                        RsaPrivateKeyBuilder::new(n.try_into()?, e.try_into()?, d.try_into()?)?
                            .set_factors(p.try_into()?, q.try_into()?)?
                            .build();

                    let key = PKey::from_rsa(key)?;

                    let mut signature: Vec<u8> = vec![];

                    const MAX_OID_SIZE: usize = 20;
                    let mut v = Vec::with_capacity(MAX_OID_SIZE + digest.len());
                    v.extend(hash_algo.oid()?);
                    v.extend(digest);

                    let mut ctx = PkeyCtx::new(&key)?;
                    ctx.sign_init()?;
                    ctx.sign_to_vec(&v, &mut signature)?;

                    Ok(mpi::Signature::RSA {
                        s: signature.into(),
                    })
                }
                (
                    PublicKeyAlgorithm::DSA,
                    mpi::PublicKey::DSA { p, q, g, y },
                    mpi::SecretKeyMaterial::DSA { x },
                ) => {
                    use openssl::dsa::{Dsa, DsaSig};
                    let dsa = Dsa::from_private_components(
                        p.try_into()?,
                        q.try_into()?,
                        g.try_into()?,
                        x.try_into()?,
                        y.try_into()?,
                    )?;
                    let key: PKey<_> = dsa.try_into()?;
                    let mut ctx = PkeyCtx::new(&key)?;
                    ctx.sign_init()?;
                    let mut signature = vec![];
                    ctx.sign_to_vec(&digest, &mut signature)?;
                    let signature = DsaSig::from_der(&signature)?;

                    Ok(mpi::Signature::DSA {
                        r: signature.r().to_vec().into(),
                        s: signature.s().to_vec().into(),
                    })
                }
                (
                    PublicKeyAlgorithm::ECDSA,
                    mpi::PublicKey::ECDSA { curve, q },
                    mpi::SecretKeyMaterial::ECDSA { scalar },
                ) => {
                    let nid = curve.try_into()?;
                    let group = EcGroup::from_curve_name(nid)?;
                    let mut ctx = BigNumContext::new()?;
                    let point = EcPoint::from_bytes(&group, q.value(), &mut ctx)?;
                    let mut private = BigNum::new_secure()?;
                    private.copy_from_slice(scalar.value())?;
                    let key = EcKey::from_private_components(&group, &private, &point)?;
                    let sig = EcdsaSig::sign(digest, &key)?;
                    Ok(mpi::Signature::ECDSA {
                        r: sig.r().into(),
                        s: sig.s().into(),
                    })
                }

                (
                    EdDSA,
                    mpi::PublicKey::EdDSA { curve, .. },
                    mpi::SecretKeyMaterial::EdDSA { scalar },
                ) => match curve {
                    Curve::Ed25519 => {
                        let scalar = scalar.value_padded(32);

                        let key =
                            PKey::private_key_from_raw_bytes(&scalar, openssl::pkey::Id::ED25519)?;

                        let mut signer = OpenSslSigner::new_without_digest(&key)?;
                        let signature = signer.sign_oneshot_to_vec(digest)?;

                        // https://tools.ietf.org/html/rfc8032#section-5.1.6
                        let (r, s) = signature.split_at(signature.len() / 2);
                        Ok(mpi::Signature::EdDSA {
                            r: r.to_vec().into(),
                            s: s.to_vec().into(),
                        })
                    }
                    _ => Err(crate::Error::UnsupportedEllipticCurve(curve.clone()).into()),
                },

                (pk_algo, _, _) => Err(crate::Error::InvalidOperation(format!(
                    "unsupported combination of algorithm {:?}, key {:?}, \
                        and secret key {:?} by OpenSSL backend",
                    pk_algo,
                    self.public(),
                    self.secret()
                ))
                .into()),
            },
        )
    }
}

impl Decryptor for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        KeyPair::public(self)
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> Result<SessionKey> {
        use crate::crypto::mpi::PublicKey;

        self.secret().map(|secret| {
            Ok(match (self.public().mpis(), secret, ciphertext) {
                (
                    PublicKey::RSA { ref e, ref n },
                    mpi::SecretKeyMaterial::RSA {
                        ref p,
                        ref q,
                        ref d,
                        ..
                    },
                    mpi::Ciphertext::RSA { ref c },
                ) => {
                    let key =
                        RsaPrivateKeyBuilder::new(n.try_into()?, e.try_into()?, d.try_into()?)?
                            .set_factors(p.try_into()?, q.try_into()?)?
                            .build();

                    let mut buf: Protected = vec![0; key.size().try_into()?].into();
                    let encrypted_len = key.private_decrypt(c.value(), &mut buf, Padding::PKCS1)?;
                    buf[..encrypted_len].into()
                }

                (
                    PublicKey::ECDH { .. },
                    mpi::SecretKeyMaterial::ECDH { .. },
                    mpi::Ciphertext::ECDH { .. },
                ) => crate::crypto::ecdh::decrypt(self.public(), secret, ciphertext)?,

                (public, secret, ciphertext) => {
                    return Err(crate::Error::InvalidOperation(format!(
                        "unsupported combination of key pair {:?}/{:?} \
                     and ciphertext {:?}",
                        public, secret, ciphertext
                    ))
                    .into())
                }
            })
        })
    }
}

impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    pub fn encrypt(&self, data: &SessionKey) -> Result<mpi::Ciphertext> {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self.pk_algo() {
            RSAEncryptSign | RSAEncrypt => match self.mpis() {
                mpi::PublicKey::RSA { e, n } => {
                    // The ciphertext has the length of the modulus.
                    let ciphertext_len = n.value().len();
                    if data.len() + 11 > ciphertext_len {
                        return Err(crate::Error::InvalidArgument(
                            "Plaintext data too large".into(),
                        )
                        .into());
                    }

                    let e = BigNum::from_slice(e.value())?;
                    let n = BigNum::from_slice(n.value())?;
                    let rsa = Rsa::<openssl::pkey::Public>::from_public_components(n, e)?;

                    // The ciphertext has the length of the modulus.
                    let mut buf = vec![0; rsa.size().try_into()?];
                    rsa.public_encrypt(data, &mut buf, Padding::PKCS1)?;
                    Ok(mpi::Ciphertext::RSA {
                        c: buf.into(),
                    })
                }
                pk => Err(crate::Error::MalformedPacket(format!(
                    "Key: Expected RSA public key, got {:?}",
                    pk
                ))
                .into()),
            },
            ECDH => crate::crypto::ecdh::encrypt(self.parts_as_public(), data),
            algo => Err(crate::Error::UnsupportedPublicKeyAlgorithm(algo).into()),
        }
    }

    /// Verifies the given signature.
    pub fn verify(
        &self,
        sig: &mpi::Signature,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> Result<()> {
        let ok = match (self.mpis(), sig) {
            (mpi::PublicKey::RSA { e, n }, mpi::Signature::RSA { s }) => {
                let e = BigNum::from_slice(e.value())?;
                let n = BigNum::from_slice(n.value())?;
                let keypair = Rsa::<openssl::pkey::Public>::from_public_components(n, e)?;
                let keypair = PKey::from_rsa(keypair)?;

                let signature = s.value();
                let mut v = vec![];
                v.extend(hash_algo.oid()?);
                v.extend(digest);

                let mut ctx = PkeyCtx::new(&keypair)?;
                ctx.verify_init()?;
                ctx.verify(&v, signature)?
            }
            (mpi::PublicKey::DSA { p, q, g, y }, mpi::Signature::DSA { r, s }) => {
                use openssl::dsa::{Dsa, DsaSig};
                let dsa = Dsa::from_public_components(
                    p.try_into()?,
                    q.try_into()?,
                    g.try_into()?,
                    y.try_into()?,
                )?;
                let key: PKey<_> = dsa.try_into()?;
                let r = r.try_into()?;
                let s = s.try_into()?;
                let signature = DsaSig::from_private_components(r, s)?;
                let mut ctx = PkeyCtx::new(&key)?;
                ctx.verify_init()?;
                ctx.verify(&digest, &signature.to_der()?)?
            }
            (mpi::PublicKey::EdDSA { curve, q }, mpi::Signature::EdDSA { r, s }) => match curve {
                Curve::Ed25519 => {
                    let public = q.decode_point(&Curve::Ed25519)?.0;

                    let key = PKey::public_key_from_raw_bytes(public, openssl::pkey::Id::ED25519)?;

                    const SIGNATURE_LENGTH: usize = 64;

                    // ed25519 expects full-sized signatures but OpenPGP allows
                    // for stripped leading zeroes, pad each part with zeroes.
                    let mut sig_bytes = [0u8; SIGNATURE_LENGTH];

                    // We need to zero-pad them at the front, because
                    // the MPI encoding drops leading zero bytes.
                    let half = SIGNATURE_LENGTH / 2;
                    sig_bytes[..half].copy_from_slice(&r.value_padded(half)?);
                    sig_bytes[half..].copy_from_slice(&s.value_padded(half)?);

                    let mut verifier = Verifier::new_without_digest(&key)?;
                    verifier.verify_oneshot(&sig_bytes, digest)?
                }
                _ => return Err(crate::Error::UnsupportedEllipticCurve(curve.clone()).into()),
            },
            (mpi::PublicKey::ECDSA { curve, q }, mpi::Signature::ECDSA { s, r }) => {
                let nid = curve.try_into()?;
                let group = EcGroup::from_curve_name(nid)?;
                let mut ctx = BigNumContext::new()?;
                let point = EcPoint::from_bytes(&group, q.value(), &mut ctx)?;
                let key = EcKey::from_public_key(&group, &point)?;
                let sig = EcdsaSig::from_private_components(
                    r.try_into()?,
                    s.try_into()?,
                )?;
                sig.verify(digest, &key)?
            }
            _ => {
                return Err(crate::Error::MalformedPacket(format!(
                    "unsupported combination of key {} and signature {:?}.",
                    self.pk_algo(),
                    sig
                ))
                .into())
            }
        };

        if ok {
            Ok(())
        } else {
            Err(crate::Error::ManipulatedMessage.into())
        }
    }
}

impl<R> Key4<SecretParts, R>
where
    R: key::KeyRole,
{
    /// Creates a new OpenPGP secret key packet for an existing X25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_cv25519<H, S, T>(
        private_key: &[u8],
        hash: H,
        sym: S,
        ctime: T,
    ) -> Result<Self>
    where
        H: Into<Option<HashAlgorithm>>,
        S: Into<Option<SymmetricAlgorithm>>,
        T: Into<Option<SystemTime>>,
    {
        let key = PKey::private_key_from_raw_bytes(private_key, openssl::pkey::Id::X25519)?;
        let public_key = key.raw_public_key()?;

        let mut private_key: Protected = key.raw_private_key().map(|key| key.into())?;
        private_key.reverse();

        use crate::crypto::ecdh;
        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::ECDH,
            mpi::PublicKey::ECDH {
                curve: Curve::Cv25519,
                hash: hash
                    .into()
                    .unwrap_or_else(|| ecdh::default_ecdh_kdf_hash(&Curve::Cv25519)),
                sym: sym
                    .into()
                    .unwrap_or_else(|| ecdh::default_ecdh_kek_cipher(&Curve::Cv25519)),
                q: MPI::new_compressed_point(&public_key),
            },
            mpi::SecretKeyMaterial::ECDH {
                scalar: private_key.into(),
            }
            .into(),
        )
    }

    /// Creates a new OpenPGP secret key packet for an existing Ed25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    {
        let key = PKey::private_key_from_raw_bytes(private_key, openssl::pkey::Id::ED25519)?;
        let public_key = key.raw_public_key()?;

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::EdDSA,
            mpi::PublicKey::EdDSA {
                curve: Curve::Ed25519,
                q: public_key.into(),
            },
            mpi::SecretKeyMaterial::EdDSA {
                scalar: mpi::MPI::new(&private_key).into(),
            }
            .into(),
        )
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have it's creation date set to `ctime` or the current time if `None`
    /// is given.
    #[allow(clippy::many_single_char_names)]
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    {
        // RFC 4880: `p < q`
        let (p, q) = if p < q { (p, q) } else { (q, p) };

        let mut big_p = BigNum::new_secure()?;
        big_p.copy_from_slice(p)?;
        let mut big_q = BigNum::new_secure()?;
        big_q.copy_from_slice(q)?;
        let n = &big_p * &big_q;

        let mut one = BigNum::new_secure()?;
        one.copy_from_slice(&[1])?;
        let big_phi = &(&big_p - &one) * &(&big_q - &one);

        let mut ctx = BigNumContext::new_secure()?;

        let mut e = BigNum::new_secure()?;
        let mut d_bn = BigNum::new_secure()?;
        d_bn.copy_from_slice(d)?;
        e.mod_inverse(&d_bn, &big_phi, &mut ctx)?; // e ≡ d⁻¹ (mod 𝜙)

        let mut u = BigNum::new_secure()?;
        u.mod_inverse(&big_p, &big_q, &mut ctx)?; // RFC 4880: u ≡ p⁻¹ (mod q)

        Self::with_secret(
            ctime.into().unwrap_or_else(crate::now),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: e.into(),
                n: n.into(),
            },
            mpi::SecretKeyMaterial::RSA {
                d: d_bn.into(),
                p: mpi::MPI::new(p).into(),
                q: mpi::MPI::new(q).into(),
                u: u.into(),
            }
            .into(),
        )
    }

    /// Generates a new RSA key with a public modulos of size `bits`.
    #[allow(clippy::many_single_char_names)]
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        let key = Rsa::generate(bits.try_into()?)?;
        let e = key.e();
        let n = key.n();
        let d = key.d();
        let p = key
            .p()
            .ok_or_else(|| crate::Error::InvalidOperation("p".into()))?;
        let q = key
            .q()
            .ok_or_else(|| crate::Error::InvalidOperation("q".into()))?;

        let mut ctx = BigNumContext::new_secure()?;
        let mut u = BigNum::new_secure()?;
        u.mod_inverse(p, q, &mut ctx)?;

        Self::with_secret(
            crate::now(),
            PublicKeyAlgorithm::RSAEncryptSign,
            mpi::PublicKey::RSA {
                e: e.into(),
                n: n.into(),
            },
            mpi::SecretKeyMaterial::RSA {
                d: d.into(),
                p: p.into(),
                q: q.into(),
                u: u.into(),
            }
            .into(),
        )
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self> {
        if for_signing && curve == Curve::Cv25519 {
            return Err(crate::Error::UnsupportedEllipticCurve(curve.clone()).into());
        }

        if !for_signing && curve == Curve::Ed25519 {
            return Err(crate::Error::UnsupportedEllipticCurve(curve.clone()).into());
        }

        if curve == Curve::Cv25519 || curve == Curve::Ed25519 {
            let key = if curve == Curve::Cv25519 {
                openssl::pkey::PKey::generate_x25519()?
            } else {
                openssl::pkey::PKey::generate_ed25519()?
            };

            let hash = crate::crypto::ecdh::default_ecdh_kdf_hash(&curve);
            let sym = crate::crypto::ecdh::default_ecdh_kek_cipher(&curve);

            let q = MPI::new_compressed_point(&key.raw_public_key()?);
            let mut scalar: Protected = key.raw_private_key().map(|key| key.into())?;

            if curve == Curve::Cv25519 {
                scalar.reverse();
            }
            let scalar = scalar.into();

            let (algo, public, private) = if for_signing {
                (
                    PublicKeyAlgorithm::EdDSA,
                    mpi::PublicKey::EdDSA { curve, q },
                    mpi::SecretKeyMaterial::EdDSA { scalar },
                )
            } else {
                (
                    PublicKeyAlgorithm::ECDH,
                    mpi::PublicKey::ECDH {
                        curve,
                        q,
                        hash,
                        sym,
                    },
                    mpi::SecretKeyMaterial::ECDH { scalar },
                )
            };
            return Self::with_secret(crate::now(), algo, public, private.into());
        }

        let nid = match curve {
            Curve::NistP256 => Nid::X9_62_PRIME256V1,
            Curve::NistP384 => Nid::SECP384R1,
            Curve::NistP521 => Nid::SECP521R1,
            _ => return Err(crate::Error::UnsupportedEllipticCurve(curve.clone()).into()),
        };

        let group = EcGroup::from_curve_name(nid)?;
        let key = EcKey::generate(&group)?;

        let hash = crate::crypto::ecdh::default_ecdh_kdf_hash(&curve);
        let sym = crate::crypto::ecdh::default_ecdh_kek_cipher(&curve);
        let mut ctx = BigNumContext::new()?;

        let q = MPI::new(&key.public_key().to_bytes(
            &group,
            PointConversionForm::COMPRESSED,
            &mut ctx,
        )?);
        let scalar = key.private_key().to_vec().into();

        let (algo, public, private) = if for_signing {
            (
                PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA { curve, q },
                mpi::SecretKeyMaterial::ECDSA { scalar },
            )
        } else {
            (
                PublicKeyAlgorithm::ECDH,
                mpi::PublicKey::ECDH {
                    curve,
                    q,
                    hash,
                    sym,
                },
                mpi::SecretKeyMaterial::ECDH { scalar },
            )
        };

        Self::with_secret(crate::now(), algo, public, private.into())
    }
}
