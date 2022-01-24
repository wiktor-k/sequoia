use anyhow::Context as _;
use std::time::SystemTime;

use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::KeyHandle;
use openpgp::Packet;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::packet::UserID;
use openpgp::parse::Parse;
use openpgp::policy::NullPolicy;
use openpgp::Result;
use openpgp::serialize::Serialize;
use openpgp::types::KeyFlags;
use openpgp::types::ReasonForRevocation;
use crate::{
    commands::cert_stub,
    Config,
    load_certs,
    open_or_stdin,
    parse_iso8601,
};

const NP: &NullPolicy = &NullPolicy::new();

enum Subcommand {
    Certificate,
    Subkey(KeyHandle),
    UserID(String),
}

impl Subcommand {
    fn is_certificate(&self) -> bool {
        matches!(self, Subcommand::Certificate)
    }

    fn userid(&self) -> Option<&str> {
        if let Subcommand::UserID(userid) = self {
            Some(userid)
        } else {
            None
        }
    }
}

pub fn dispatch(config: Config, m: &clap::ArgMatches) -> Result<()> {
    let (subcommand, m) = match m.subcommand() {
        ("certificate", Some(m)) => (Subcommand::Certificate, m),
        ("subkey", Some(m)) => {
            let subkey = m.value_of("subkey").expect("required");
            let kh: KeyHandle = subkey
                .parse()
                .context(
                    format!("Parsing {:?} as an OpenPGP fingerprint or Key ID",
                            subkey))?;

            (Subcommand::Subkey(kh), m)
        }
        ("userid", Some(m)) => {
            let userid = m.value_of("userid").expect("required");

            (Subcommand::UserID(userid.into()), m)
        }
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
        Subcommand::Certificate | Subcommand::Subkey(_) => {
            match &*reason {
                "compromised" => ReasonForRevocation::KeyCompromised,
                "superseded" => ReasonForRevocation::KeySuperseded,
                "retired" => ReasonForRevocation::KeyRetired,
                "unspecified" => ReasonForRevocation::Unspecified,
                _ => panic!("invalid values should be caught by clap"),
            }
        }
        Subcommand::UserID(_) => {
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

            let (critical, name) =
                if let Some(name) = name.strip_prefix('!') {
                    (true, name)
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

    revoke(
        config,
        private_key_store,
        cert,
        subcommand,
        secret,
        binary,
        time,
        reason,
        message,
        &notations)?;

    Ok(())
}

fn revoke(config: Config,
          private_key_store: Option<&str>,
          cert: openpgp::Cert,
          subcommand: Subcommand,
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
            if let Some(time) = time {
                return Err(anyhow::anyhow!("\
No certification key found: the key specified with --revocation-key \
does not contain a certification key with secret key material.  \
Perhaps this is because no certification keys are valid at the time \
you specified ({})",
                    chrono::DateTime::<chrono::offset::Utc>::from(time)));
            } else {
                return Err(anyhow::anyhow!("\
No certification key found: the key specified with --revocation-key \
does not contain a certification key with secret key material"));
            }
        }
    } else {
        if let Ok(keys) = super::get_certification_keys(&[ &cert ],
                                                        &config.policy,
                                                        private_key_store,
                                                        time) {
            assert_eq!(keys.len(), 1);
            (&cert, keys.into_iter().next().expect("have one"))
        } else {
            if let Some(time) = time {
                return Err(anyhow::anyhow!("\
No certification key found: --revocation-key not provided and the
certificate to revoke does not contain a certification key with secret
key material.  Perhaps this is because no certification keys are valid at
the time you specified ({})",
                    chrono::DateTime::<chrono::offset::Utc>::from(time)));
            } else {
                return Err(anyhow::anyhow!("\
No certification key found: --revocation-key not provided and the
certificate to revoke does not contain a certification key with secret
key material"));
            }
        }
    };

    let first_party = secret.fingerprint() == cert.fingerprint();
    let mut subkey = None;

    let rev: Packet = match subcommand {
        Subcommand::UserID(ref userid) => {
            // Create a revocation for a User ID.

            // Unless force is specified, we require the User ID to
            // have a valid self signature under the Null policy.  We
            // use the Null policy and not the standard policy,
            // because it is still useful to revoke a User ID whose
            // self signature is no longer valid.  For instance, the
            // binding signature may use SHA-1.
            if ! config.force {
                let vc = cert.with_policy(NP, None)?;
                let present = vc.userids().any(|u| {
                    u.value() == userid.as_bytes()
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
            let rev = rev.build(
                &mut signer, &cert, &UserID::from(userid.as_str()), None)?;
            Packet::Signature(rev)
        }
        Subcommand::Subkey(ref subkey_fpr) => {
            let vc = cert.with_policy(NP, None)?;

            for k in vc.keys().subkeys() {
                if subkey_fpr.aliases(KeyHandle::from(k.fingerprint())) {
                    subkey = Some(k);
                    break;
                }
            }

            if let Some(ref subkey) = subkey {
                let mut rev = SubkeyRevocationBuilder::new()
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
                let rev = rev.build(
                    &mut signer, &cert, subkey.key(), None)?;
                Packet::Signature(rev)
            } else {
                eprintln!("Subkey {} not found.\nValid subkeys:",
                          subkey_fpr.to_spaced_hex());
                let mut have_valid = false;
                for k in vc.keys().subkeys() {
                    have_valid = true;
                    eprintln!("  - {} {} [{:?}]",
                              k.fingerprint().to_hex(),
                              chrono::DateTime::<chrono::offset::Utc>
                                  ::from(k.creation_time())
                                  .date(),
                              k.key_flags().unwrap_or_else(KeyFlags::empty));
                }
                if ! have_valid {
                    eprintln!("  - Certificate has no subkeys.");
                }
                return Err(anyhow::anyhow!("\
The certificate does not contain the specified subkey."));
            }
        }
        Subcommand::Certificate => {
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
        }
    };

    let mut stub = None;
    let packets: Vec<Packet> = if first_party && subcommand.is_certificate() {
        vec![ rev ]
    } else {
        let mut s = match cert_stub(
            cert.clone(), &config.policy, time,
            subcommand.userid().map(UserID::from).as_ref())
        {
            Ok(stub) => stub,
            // We failed to create a stub.  Just use the original
            // certificate as is.
            Err(_) => cert.clone(),
        };

        if let Some(ref subkey) = subkey {
            s = s.insert_packets([
                Packet::from(subkey.key().clone()),
                Packet::from(subkey.binding_signature().clone())
            ])?;
        }

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
        let cert = stub.as_ref().unwrap_or(&cert);

        // Add some more helpful ASCII-armor comments.
        let mut more: Vec<String> = Vec::new();

        // First, the thing that is being revoked.
        match subcommand {
            Subcommand::Certificate => {
                more.push(
                    "including a revocation for the certificate".to_string());
            }
            Subcommand::Subkey(_) => {
                more.push(
                    "including a revocation to revoke the subkey".to_string());
                more.push(subkey.unwrap().fingerprint().to_spaced_hex());
            }
            Subcommand::UserID(raw) => {
                more.push(
                    "including a revocation to revoke the User ID".to_string());
                more.push(format!("{:?}", raw));
            }
        }

        if ! first_party {
            // Then if it was issued by a third-party.
            more.push("issued by".to_string());
            more.push(secret.fingerprint().to_spaced_hex());
            if let Ok(vc) = cert.with_policy(&config.policy, time) {
                if let Ok(uid) = vc.primary_userid() {
                    let uid = String::from_utf8_lossy(uid.value());
                    // Truncate it, if it is too long.
                    more.push(
                        format!("{:?}",
                                uid.chars().take(70).collect::<String>()));
                }
            }
        }

        let headers = cert.armor_headers();
        let headers: Vec<(&str, &str)> = headers
            .iter()
            .map(|s| ("Comment", s.as_str()))
            .chain(
                more
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
