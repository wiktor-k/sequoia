use anyhow::Context as _;
use std::time::SystemTime;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::Packet;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::policy::NullPolicy;
use openpgp::Result;
use openpgp::serialize::Serialize;
use openpgp::types::ReasonForRevocation;
use crate::{
    commands::cert_stub,
    Config,
    load_certs,
    open_or_stdin,
    parse_iso8601,
};

const NP: &NullPolicy = &NullPolicy::new();

pub fn dispatch(config: Config, m: &clap::ArgMatches) -> Result<()> {
    enum Subcommand {
        Certificate,
        UserID,
    }

    let (subcommand, m) = match m.subcommand() {
        ("certificate", Some(m)) => (Subcommand::Certificate, m),
        ("userid", Some(m)) => (Subcommand::UserID, m),
        _ => unreachable!(),
    };

    let input = m.value_of("input");
    let input = open_or_stdin(input)?;
    let cert = CertParser::from_reader(input)?.collect::<Vec<_>>();
    let cert = match cert.len() {
        0 => Err(anyhow::anyhow!("No certificates provided."))?,
        1 => cert.into_iter().next().expect("have one")?,
        _ => Err(
            anyhow::anyhow!("Multiple certificates provided."))?,
    };

    let secret: Option<&str> = m.value_of("secret-key-file");
    let secret = load_certs(secret.into_iter())?;
    if secret.len() > 1 {
        Err(anyhow::anyhow!("Multiple secret keys provided."))?;
    }
    let secret = secret.into_iter().next();

    let private_key_store = m.value_of("private-key-store");

    let binary = m.is_present("binary");

    let time = if let Some(time) = m.value_of("time") {
        Some(parse_iso8601(time, chrono::NaiveTime::from_hms(0, 0, 0))
             .context(format!("Bad value passed to --time: {:?}",
                              time))?.into())
    } else {
        None
    };

    let reason = m.value_of("reason").expect("required");
    let reason = match subcommand {
        Subcommand::Certificate => {
            match &*reason {
                "compromised" => ReasonForRevocation::KeyCompromised,
                "superseded" => ReasonForRevocation::KeySuperseded,
                "retired" => ReasonForRevocation::KeyRetired,
                "unspecified" => ReasonForRevocation::Unspecified,
                _ => panic!("invalid values should be caught by clap"),
            }
        }
        Subcommand::UserID => {
            match &*reason {
                "retired" => ReasonForRevocation::UIDRetired,
                "unspecified" => ReasonForRevocation::Unspecified,
                _ => panic!("invalid values should be caught by clap"),
            }
        }
    };

    let message: &str = m.value_of("message").expect("required");

    // Each --notation takes two values.  The iterator
    // returns them one at a time, however.
    let mut notations: Vec<(bool, NotationData)> = Vec::new();
    if let Some(mut n) = m.values_of("notation") {
        while let Some(name) = n.next() {
            let value = n.next().unwrap();

            let (critical, name) = if !name.is_empty()
                && name.starts_with('!')
            {
                (true, &name[1..])
            } else {
                (false, name)
            };

            notations.push(
                (critical,
                 NotationData::new(
                     name, value,
                     NotationDataFlags::empty().set_human_readable())));
        }
    }

    match subcommand {
        Subcommand::Certificate => {
            revoke(
                config,
                private_key_store,
                cert,
                None,
                secret,
                binary,
                time,
                reason,
                message,
                &notations)?;
        }
        Subcommand::UserID => {
            let userid = m.value_of("userid").expect("required");

            revoke(
                config,
                private_key_store,
                cert,
                Some(userid),
                secret,
                binary,
                time,
                reason,
                message,
                &notations)?;
        }
    }

    Ok(())
}

fn revoke(config: Config,
          private_key_store: Option<&str>,
          cert: openpgp::Cert,
          userid: Option<&str>,
          secret: Option<openpgp::Cert>,
          binary: bool,
          time: Option<SystemTime>,
          reason: ReasonForRevocation,
          message: &str,
          notations: &[(bool, NotationData)])
    -> Result<()>
{
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

    let rev: Packet = if let Some(userid) = userid {
        // Create a revocation for a User ID.

        // Unless force is specified, we require the User ID to have a
        // valid self signature under the Null policy.  We use the
        // Null policy and not the standard policy, because it is
        // still useful to revoke a User ID whose self signature is no
        // longer valid.  For instance, the binding signature may use
        // SHA-1.
        if ! config.force {
            let vc = cert.with_policy(NP, None)?;
            let present = vc.userids().any(|u| {
                if let Ok(u) = String::from_utf8(u.value().to_vec()) {
                    if u == userid {
                        return true;
                    }
                }
                false
            });

            if ! present {
                eprintln!("User ID: '{}' not found.\nValid User IDs:",
                          userid);
                let mut have_valid = false;
                for ua in vc.userids() {
                    if let Ok(u) = std::str::from_utf8(ua.userid().value()) {
                        have_valid = true;
                        eprintln!("  - {}", u);
                    }
                }
                if ! have_valid {
                    eprintln!("  - Certificate has no valid User IDs.");
                }
                return Err(anyhow::anyhow!("\
The certificate does not contain the specified User ID.  To create
a revocation certificate for that User ID anyways, specify '--force'"));
            }
        }

        let mut rev = UserIDRevocationBuilder::new()
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
        let rev = rev.build(&mut signer, &cert, &UserID::from(userid), None)?;
        Packet::Signature(rev)
    } else {
        // Create a revocation for the certificate.
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
        Packet::Signature(rev)
    };

    let mut stub = None;
    let packets: Vec<Packet> = if first_party && userid.is_none() {
        vec![ rev ]
    } else {
        let s = match cert_stub(cert.clone(), &config.policy, time,
                                userid.map(UserID::from).as_ref())
        {
            Ok(stub) => stub,
            // We failed to create a stub.  Just use the original
            // certificate as is.
            Err(_) => cert.clone(),
        };

        stub = Some(s.clone());

        s.insert_packets(rev)?
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

        let headers = stub.unwrap_or(cert).armor_headers();
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
