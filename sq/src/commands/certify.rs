use std::time::{SystemTime, Duration};

use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::packet::prelude::*;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;

use crate::Config;
use crate::parse_duration;
use crate::parse_notations;
use crate::SECONDS_IN_YEAR;
use crate::commands::get_certification_keys;
use crate::commands::GetKeysOptions;

use crate::sq_cli::certify::CertifyCommand;

pub fn certify(config: Config, c: CertifyCommand)
    -> Result<()>
{
    let certifier = c.certifier;
    let cert = c.certificate;
    let userid = c.userid;

    let certifier = Cert::from_file(certifier)?;
    let private_key_store = c.private_key_store;
    let cert = Cert::from_file(cert)?;

    let trust_depth: u8 = c.depth;
    let trust_amount: u8 = c.amount;
    let regex = c.regex;
    if trust_depth == 0 && !regex.is_empty() {
        return Err(
            anyhow::format_err!("A regex only makes sense \
                                 if the trust depth is greater than 0"));
    }

    let local = c.local;
    let non_revocable = c.non_revocable;

    let time = if let Some(t) = c.time {
        let time = SystemTime::from(
            crate::parse_iso8601(&t, chrono::NaiveTime::from_hms(0, 0, 0))
                .context(format!("Parsing --time {}", t))?);
        Some(time)
    } else {
        None
    };

    let expires = c.expires;
    let expires_in = c.expires_in;

    let vc = cert.with_policy(&config.policy, time)?;

    // Find the matching User ID.
    let mut u = None;
    for ua in vc.userids() {
        if let Ok(a_userid) = std::str::from_utf8(ua.userid().value()) {
            if a_userid == userid {
                u = Some(ua.userid());
                break;
            }
        }
    }

    let userid = if let Some(userid) = u {
        userid
    } else {
        eprintln!("User ID: '{}' not found.\nValid User IDs:", userid);
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
        return Err(anyhow::format_err!("No matching User ID found"));
    };

    // Create the certification.
    let mut builder
        = SignatureBuilder::new(SignatureType::GenericCertification);

    if trust_depth != 0 || trust_amount != 120 {
        builder = builder.set_trust_signature(trust_depth, trust_amount)?;
    }

    for regex in regex {
        builder = builder.add_regular_expression(regex)?;
    }

    if local {
        builder = builder.set_exportable_certification(false)?;
    }

    if non_revocable {
        builder = builder.set_revocable(false)?;
    }

    // Creation time.
    if let Some(time) = time {
        builder = builder.set_signature_creation_time(time)?;
    }

    match (expires, expires_in) {
        (None, None) =>
            // Default expiration.
            builder = builder.set_signature_validity_period(
                Duration::new(5 * SECONDS_IN_YEAR, 0))?,
        (Some(t), None) if t == "never" =>
            // The default is no expiration; there is nothing to do.
            (),
        (Some(t), None) => {
            let now = builder.signature_creation_time()
                .unwrap_or_else(std::time::SystemTime::now);
            let expiration = SystemTime::from(
                crate::parse_iso8601(&t, chrono::NaiveTime::from_hms(0, 0, 0))?);
            let validity = expiration.duration_since(now)?;
            builder = builder.set_signature_creation_time(now)?
                .set_signature_validity_period(validity)?;
        },
        (None, Some(d)) if d == "never" =>
            // The default is no expiration; there is nothing to do.
            (),
        (None, Some(d)) => {
            let d = parse_duration(&d)?;
            builder = builder.set_signature_validity_period(d)?;
        },
        (Some(_), Some(_)) => unreachable!("conflicting args"),
    }

    let notations = parse_notations(c.notation.unwrap_or_default())?;
    for (critical, n) in notations {
        builder = builder.add_notation(
            n.name(),
            n.value(),
            NotationDataFlags::empty().set_human_readable(),
            critical)?;
    };

    let mut options = Vec::new();
    if c.allow_not_alive_certifier {
        options.push(GetKeysOptions::AllowNotAlive);
    }
    if c.allow_revoked_certifier {
        options.push(GetKeysOptions::AllowRevoked);
    }

    // Sign it.
    let signers = get_certification_keys(
        &[certifier], &config.policy,
        private_key_store.as_deref(),
        time,
        Some(&options))?;
    assert_eq!(signers.len(), 1);
    let mut signer = signers.into_iter().next().unwrap();

    let certification = builder
        .sign_userid_binding(
            &mut signer,
            cert.primary_key().component(),
            userid)?;
    let cert = cert.insert_packets(certification.clone())?;
    assert!(cert.clone().into_packets().any(|p| {
        match p {
            Packet::Signature(sig) => sig == certification,
            _ => false,
        }
    }));


    // And export it.
    let mut message = config.create_or_stdout_pgp(
        c.output.as_deref(),
        c.binary,
        sequoia_openpgp::armor::Kind::PublicKey,
    )?;
    cert.serialize(&mut message)?;
    message.finalize()?;

    Ok(())
}
