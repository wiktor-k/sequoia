use anyhow::Context as _;
use std::time::SystemTime;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::cert::CertRevocationBuilder;
use openpgp::Packet;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::Result;
use openpgp::serialize::Serialize;
use openpgp::types::ReasonForRevocation;
use crate::{
    commands::cert_stub,
    Config,
};

pub struct RevokeOpts<'a> {
    pub config: Config<'a>,
    pub private_key_store: Option<&'a str>,
    pub cert: openpgp::Cert,
    pub secret: Option<openpgp::Cert>,
    pub binary: bool,
    pub time: Option<SystemTime>,
    pub reason: ReasonForRevocation,
    pub message: &'a str,
    pub notations: &'a [(bool, NotationData)],
}

pub fn revoke_certificate(opts: RevokeOpts) -> Result<()>
{
    let config = opts.config;
    let private_key_store = opts.private_key_store;
    let cert = opts.cert;
    let secret = opts.secret;
    let binary = opts.binary;
    let time = opts.time;
    let reason = opts.reason;
    let message = opts.message;
    let notations = opts.notations;

    let mut output = config.create_or_stdout_safe(None)?;

    let (secret, mut signer) = if let Some(secret) = secret.as_ref() {
        if let Ok(keys) = super::get_certification_keys(&[ secret ],
                                                        &config.policy,
                                                        private_key_store,
                                                        time) {
            assert_eq!(keys.len(), 1);
            (secret, keys.into_iter().next().expect("have one"))
        } else {
            return Err(anyhow::anyhow!("\
No certification key found: the key specified with --revocation-key \
does not contain a certification key with secret key material"));

        }
    } else {
        if let Ok(keys) = super::get_certification_keys(&[ &cert ],
                                                        &config.policy,
                                                        private_key_store,
                                                        time) {
            assert_eq!(keys.len(), 1);
            (&cert, keys.into_iter().next().expect("have one"))
        } else {
            return Err(anyhow::anyhow!("\
No certification key found: --revocation-key not provided and the
certificate to revoke does not contain a certification key with secret
key material"));
        }
    };

    let first_party = secret.fingerprint() == cert.fingerprint();

    let mut rev = CertRevocationBuilder::new()
        .set_reason_for_revocation(reason, message.as_bytes())?;
    if let Some(time) = time {
        rev = rev.set_signature_creation_time(time)?;
    }
    for (critical, notation) in notations {
        rev = rev.add_notation(notation.name(),
                               notation.value(),
                               Some(notation.flags().clone()),
                               *critical)?;
    }
    let rev = rev.build(&mut signer, &cert, None)?;
    let rev = Packet::Signature(rev);

    let packets: Vec<Packet> = if first_party {
        vec![ rev ]
    } else {
        cert_stub(cert.clone(), &config.policy, time)
            // If we fail to minimize the the certificate, just use as
            // it.
            .unwrap_or_else(|_err| cert.clone())
            // Now add the revocation certificate.
            .insert_packets(rev)?
            .into_packets()
            .collect()
    };

    if binary {
        for p in packets {
            p.serialize(&mut output)
                .context("serializing revocation certificate")?;
        }
    } else {
        // Add some helpful ASCII-armor comments.
        let mut revoker_fpr = None;
        let mut revoker_uid = None;

        if ! first_party {
            if let Ok(secret) = secret.with_policy(&config.policy, time) {
                if let Ok(uid) = secret.primary_userid() {
                    revoker_uid = Some(uid);
                }
            }

            revoker_fpr = Some(secret.fingerprint());
        }

        let preface = match (revoker_fpr, revoker_uid) {
            (Some(fpr), Some(uid)) => {
                let uid = String::from_utf8_lossy(uid.value());
                // Truncate it, if it is too long.
                if uid.len() > 40 {
                    &uid[..40]
                } else {
                    &uid
                };

                vec![format!("Revocation certificate by {}",
                             fpr.to_spaced_hex()),
                     format!("({:?}) for:", uid)]
            }
            (Some(fpr), None) => {
                vec![format!("Revocation certificate by {} for:",
                             fpr.to_spaced_hex())]
            }
            (_, _) => {
                vec![("Revocation certificate for:".into())]
            }
        };

        let headers = cert.armor_headers();
        let headers: Vec<_> = preface
            .iter()
            .map(|s| ("Comment", s.as_str()))
            .chain(
                headers
                    .iter()
                    .map(|value| ("Comment", value.as_str())))
            .collect();

        let mut writer = armor::Writer::with_headers(
            &mut output, armor::Kind::PublicKey, headers)?;
        for p in packets {
            p.serialize(&mut writer)
                .context("serializing revocation certificate")?;
        }
        writer.finalize()?;
    }

    Ok(())
}
