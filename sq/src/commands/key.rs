use anyhow::Context as _;
use itertools::Itertools;
use std::time::{SystemTime, Duration};

use crate::openpgp::KeyHandle;
use crate::openpgp::Packet;
use crate::openpgp::Result;
use crate::openpgp::armor::{Writer, Kind};
use crate::openpgp::cert::prelude::*;
use crate::openpgp::packet::prelude::*;
use crate::openpgp::packet::signature::subpacket::SubpacketTag;
use crate::openpgp::parse::Parse;
use crate::openpgp::policy::{Policy, HashAlgoSecurity};
use crate::openpgp::serialize::Serialize;
use crate::openpgp::types::KeyFlags;
use crate::openpgp::types::SignatureType;

use crate::{
    open_or_stdin,
};
use crate::commands::get_primary_keys;
use crate::Config;
use crate::SECONDS_IN_YEAR;
use crate::parse_duration;
use crate::decrypt_key;

use crate::sq_cli::KeyCommand;
use crate::sq_cli::KeyGenerateCommand;
use crate::sq_cli::KeyPasswordCommand;
use crate::sq_cli::KeyUseridCommand;
use crate::sq_cli::KeyUseridAddCommand;
use crate::sq_cli::KeyExtractCertCommand;
use crate::sq_cli::KeyAdoptCommand;
use crate::sq_cli::KeyAttestCertificationsCommand;
use crate::sq_cli::KeySubcommands::*;

pub fn dispatch(config: Config, command: KeyCommand) -> Result<()> {
    match command.subcommand {
        Generate(c) => generate(config, c)?,
        Password(c) => password(config, c)?,
        Userid(c) => userid(config, c)?,
        ExtractCert(c) => extract_cert(config, c)?,
        Adopt(c) => adopt(config, c)?,
        AttestCertifications(c) => attest_certifications(config, c)?,
    }
    Ok(())
}

fn generate(config: Config, command: KeyGenerateCommand) -> Result<()> {
    let mut builder = CertBuilder::new();

    // User ID
    match command.userid {
        Some(uids) => for uid in uids {
            builder = builder.add_userid(uid);
        },
        None => {
            eprintln!("No user ID given, using direct key signature");
        }
    }

    // Creation time.
    if let Some(t) = command.creation_time {
        builder = builder.set_creation_time(SystemTime::from(t.time));
    };

    // Expiration.
    match (command.expires, command.expires_in) {
        (None, None) => // Default expiration.
            builder = builder.set_validity_period(
                Some(Duration::new(3 * SECONDS_IN_YEAR, 0))),
        (Some(t), None) if t == "never" =>
            builder = builder.set_validity_period(None),
        (Some(t), None) => {
            let now = builder.creation_time()
                .unwrap_or_else(std::time::SystemTime::now);
            let expiration = SystemTime::from(
                crate::parse_iso8601(&t, chrono::NaiveTime::from_hms(0, 0, 0))?);
            let validity = expiration.duration_since(now)?;
            builder = builder.set_creation_time(now)
                .set_validity_period(validity);
        },
        (None, Some(d)) if d == "never" =>
            builder = builder.set_validity_period(None),
        (None, Some(d)) => {
            let d = parse_duration(&d)?;
            builder = builder.set_validity_period(Some(d));
        },
        (Some(_), Some(_)) => unreachable!("conflicting args"),
    }

    // Cipher Suite
    use crate::sq_cli::KeyCipherSuite::*;
    match command.cipher_suite {
        Rsa3k => {
            builder = builder.set_cipher_suite(CipherSuite::RSA3k);
        }
        Rsa4k => {
            builder = builder.set_cipher_suite(CipherSuite::RSA4k);
        }
        Cv25519 => {
            builder = builder.set_cipher_suite(CipherSuite::Cv25519);
        }
    }

    // Signing Capability
    match (command.can_sign, command.cannot_sign) {
        (false, false) | (true, false) => {
            builder = builder.add_signing_subkey();
        }
        (false, true) => { /* no signing subkey */ }
        (true, true) => {
            return Err(
                anyhow::anyhow!("Conflicting arguments --can-sign and --cannot-sign"));
        }
    }

    // Authentication Capability
    match (command.can_authenticate, command.cannot_authenticate) {
        (false, false) | (true, false) => {
            builder = builder.add_authentication_subkey()
        }
        (false, true) => { /* no authentication subkey */ }
        (true, true) => {
            return Err(
                anyhow::anyhow!("Conflicting arguments --can-authenticate and\
                                --cannot-authenticate"));
        }
    }

    // Encryption Capability
    use crate::sq_cli::KeyEncryptPurpose::*;
    match (command.can_encrypt, command.cannot_encrypt) {
        (Some(Universal), false) | (None, false) => {
            builder = builder.add_subkey(KeyFlags::empty()
                                         .set_transport_encryption()
                                         .set_storage_encryption(),
                                         None,
                                         None);
        }
        (Some(Storage), false) => {
            builder = builder.add_storage_encryption_subkey();
        }
        (Some(Transport), false) => {
            builder = builder.add_transport_encryption_subkey();
        }
        (None, true) => { /* no encryption subkey */ }
        (Some(_), true) => {
            return Err(
                anyhow::anyhow!("Conflicting arguments --can-encrypt and \
                             --cannot-encrypt"));
        }
    }

    if command.with_password {
        let p0 = rpassword::read_password_from_tty(Some(
            "Enter password to protect the key: "))?.into();
        let p1 = rpassword::read_password_from_tty(Some(
            "Repeat the password once more: "))?.into();

        if p0 == p1 {
            builder = builder.set_password(Some(p0));
        } else {
            return Err(anyhow::anyhow!("Passwords do not match."));
        }
    }

    // Generate the key
    let (cert, rev) = builder.generate()?;

    // Export
    if command.export.is_some() {
        let (key_path, rev_path) =
            match (command.export.as_deref(), command.rev_cert.as_deref()) {
                (Some("-"), Some("-")) =>
                    ("-".to_string(), "-".to_string()),
                (Some("-"), Some(ref rp)) =>
                    ("-".to_string(), rp.to_string()),
                (Some("-"), None) =>
                    return Err(
                        anyhow::anyhow!("Missing arguments: --rev-cert is mandatory \
                                     if --export is '-'.")),
                (Some(ref kp), None) =>
                    (kp.to_string(), format!("{}.rev", kp)),
                (Some(ref kp), Some("-")) =>
                    (kp.to_string(), "-".to_string()),
                (Some(ref kp), Some(ref rp)) =>
                    (kp.to_string(), rp.to_string()),
                _ =>
                    return Err(
                        anyhow::anyhow!("Conflicting arguments --rev-cert and \
                                     --export")),
            };

        let headers = cert.armor_headers();

        // write out key
        {
            let headers: Vec<_> = headers.iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();

            let w = config.create_or_stdout_safe(Some(&key_path))?;
            let mut w = Writer::with_headers(w, Kind::SecretKey, headers)?;
            cert.as_tsk().serialize(&mut w)?;
            w.finalize()?;
        }

        // write out rev cert
        {
            let mut headers: Vec<_> = headers.iter()
                .map(|value| ("Comment", value.as_str()))
                .collect();
            headers.insert(0, ("Comment", "Revocation certificate for"));

            let w = config.create_or_stdout_safe(Some(&rev_path))?;
            let mut w = Writer::with_headers(w, Kind::Signature, headers)?;
            Packet::Signature(rev).serialize(&mut w)?;
            w.finalize()?;
        }
    } else {
        return Err(
            anyhow::anyhow!("Saving generated key to the store isn't implemented \
                         yet."));
    }

    Ok(())
}

fn password(config: Config, command: KeyPasswordCommand) -> Result<()> {
    let input = open_or_stdin(command.io.input.as_deref())?;
    let key = Cert::from_reader(input)?;

    if ! key.is_tsk() {
        return Err(anyhow::anyhow!("Certificate has no secrets"));
    }

    // First, decrypt all secrets.
    let passwords = &mut Vec::new();
    let mut decrypted: Vec<Packet> = vec![decrypt_key(
        key.primary_key().key().clone().parts_into_secret()?,
        passwords,
    )?
    .into()];
    for ka in key.keys().subkeys().secret() {
        decrypted.push(decrypt_key(
            ka.key().clone().parts_into_secret()?,
            passwords)?.into());
    }
    let mut key = key.insert_packets(decrypted)?;
    assert_eq!(key.keys().secret().count(),
               key.keys().unencrypted_secret().count());

    let new_password = if command.clear {
        None
    } else {
        let prompt_0 =
            rpassword::read_password_from_tty(Some("New password: "))
            .context("Error reading password")?;
        let prompt_1 =
            rpassword::read_password_from_tty(Some("Repeat new password: "))
            .context("Error reading password")?;

        if prompt_0 != prompt_1 {
            return Err(anyhow::anyhow!("Passwords do not match"));
        }

        if prompt_0.is_empty() {
            // Empty password means no password.
            None
        } else {
            Some(prompt_0.into())
        }
    };

    if let Some(new) = new_password {
        let mut encrypted: Vec<Packet> = vec![
            key.primary_key().key().clone().parts_into_secret()?
                .encrypt_secret(&new)?.into()
        ];
        for ka in key.keys().subkeys().unencrypted_secret() {
            encrypted.push(
                ka.key().clone().parts_into_secret()?
                    .encrypt_secret(&new)?.into());
        }
        key = key.insert_packets(encrypted)?;
    }

    let mut output = config.create_or_stdout_safe(command.io.output.as_deref())?;
    if command.binary {
        key.as_tsk().serialize(&mut output)?;
    } else {
        key.as_tsk().armored().serialize(&mut output)?;
    }
    Ok(())
}

fn extract_cert(config: Config, command: KeyExtractCertCommand) -> Result<()> {
    let input = open_or_stdin(command.io.input.as_deref())?;
    let mut output = config.create_or_stdout_safe(command.io.output.as_deref())?;

    let cert = Cert::from_reader(input)?;
    if command.binary {
        cert.serialize(&mut output)?;
    } else {
        cert.armored().serialize(&mut output)?;
    }
    Ok(())
}

fn userid(config: Config, command: KeyUseridCommand) -> Result<()> {
    match command {
        KeyUseridCommand::Add(c) => userid_add(config, c)?,
    }

    Ok(())
}

fn userid_add(config: Config, command: KeyUseridAddCommand) -> Result<()> {
    let input = open_or_stdin(command.io.input.as_deref())?;
    let key = Cert::from_reader(input)?;

    // Fail if any of the User IDs to add already exist in the ValidCert
    let key_userids: Vec<_> =
        key.userids().map(|u| u.userid().value()).collect();
    let exists: Vec<_> =  command.userid.iter()
        .filter(|s| key_userids.contains(&s.as_bytes()))
        .collect();
    if ! exists.is_empty() {
        return Err(anyhow::anyhow!(
            "The certificate already contains the User ID(s) {}.",
            exists.iter().map(|s| format!("{:?}", s)).join(", ")));
    }

    let creation_time =
        command.creation_time.map(|t| SystemTime::from(t.time));

    // If a password is needed to use the key, the user will be prompted.
    let pk = get_primary_keys(&[key.clone()], &config.policy,
                              command.private_key_store.as_deref(),
                              creation_time, None)?;

    assert_eq!(pk.len(), 1, "Expect exactly one result from get_primary_keys()");
    let mut pk = pk.into_iter().next().unwrap();

    let vcert = key.with_policy(&config.policy, creation_time)
        .with_context(|| format!("Certificate {} is not valid",
                                 key.fingerprint()))?;

    // Use the primary User ID or direct key signature as template for the
    // SignatureBuilder.
    //
    // XXX: Long term, this functionality belongs next to
    // openpgp/src/cert/builder/key.rs.
    let mut sb =
        if let Ok(primary_user_id) = vcert.primary_userid() {
            SignatureBuilder::from(primary_user_id.binding_signature().clone())
        } else if let Ok(direct_key_sig) = vcert.direct_key_signature() {
            SignatureBuilder::from(direct_key_sig.clone())
                .set_type(SignatureType::PositiveCertification)
        } else {
            // If there is neither a valid uid binding signature, nor a
            // valid direct key signature, we shouldn't have gotten a
            // ValidCert above.
            unreachable!("ValidCert has to have one of the above.")
        };

    // Remove bad algorithms from preferred algorithm subpackets,
    // and make sure preference lists contain at least one good algorithm.

    // - symmetric_algorithms
    let mut symmetric_algorithms: Vec<_> =
        sb.preferred_symmetric_algorithms().unwrap_or(&[]).to_vec();
    symmetric_algorithms
        .retain(|algo| config.policy.symmetric_algorithm(*algo).is_ok());
    if symmetric_algorithms.is_empty() {
        symmetric_algorithms.push(Default::default());
    }
    sb = sb.set_preferred_symmetric_algorithms(symmetric_algorithms)?;

    // - hash_algorithms
    let mut hash_algorithms: Vec<_> =
        sb.preferred_hash_algorithms().unwrap_or(&[]).to_vec();
    hash_algorithms.retain(|algo|
        config.policy
            .hash_cutoff(*algo, HashAlgoSecurity::CollisionResistance)
            .map(|cutoff| cutoff.lt(&SystemTime::now()))
            .unwrap_or(true)
    );
    if hash_algorithms.is_empty() {
        hash_algorithms.push(Default::default());
    }
    sb = sb.set_preferred_hash_algorithms(hash_algorithms)?;


    // Remove the following types of SubPacket, if they exist
    const REMOVE_SUBPACKETS: &[SubpacketTag] = &[
        // The Signature should be exportable.
        // https://openpgp-wg.gitlab.io/rfc4880bis/#name-exportable-certification
        // "If this packet is not present, the certification is exportable;
        // it is equivalent to a flag containing a 1."
        SubpacketTag::ExportableCertification,

        // PreferredAEADAlgorithms has been removed by WG.
        // It was replaced by `39  Preferred AEAD Ciphersuites`,
        //  see https://openpgp-wg.gitlab.io/rfc4880bis/#section-5.2.3.5-7)
        SubpacketTag::PreferredAEADAlgorithms,

        // Strip the primary userid SubPacket
        // (don't implicitly make a User ID primary)
        SubpacketTag::PrimaryUserID,

        // Other SubPacket types that shouldn't be in use in this context
        SubpacketTag::TrustSignature,
        SubpacketTag::RegularExpression,
        SubpacketTag::SignersUserID,
        SubpacketTag::ReasonForRevocation,
        SubpacketTag::SignatureTarget,
        SubpacketTag::EmbeddedSignature,
        SubpacketTag::AttestedCertifications,
    ];

    sb = sb.modify_hashed_area(|mut subpacket_area| {
        REMOVE_SUBPACKETS.iter()
            .for_each(|sp| subpacket_area.remove_all(*sp));

        Ok(subpacket_area)
    })?;

    // New User ID should only be made primary if explicitly specified by user.
    // xxx: add a parameter to set a new user id as primary?


    // Collect packets to add to the key (new User IDs and binding signatures)
    let mut add: Vec<Packet> = vec![];

    // Make new User IDs and binding signatures
    for uid in command.userid {
        let uid: UserID = uid.into();
        add.push(uid.clone().into());

        // Creation time.
        if let Some(t) = creation_time {
            sb = sb.set_signature_creation_time(t)?;
        };

        let binding = uid.bind(&mut pk, &key, sb.clone())?;
        add.push(binding.into());
    }

    // Merge additional User IDs into key
    let cert = key.insert_packets(add)?;

    let mut sink = config.create_or_stdout_safe(command.io.output.as_deref())?;
    if command.binary {
        cert.as_tsk().serialize(&mut sink)?;
    } else {
        cert.as_tsk().armored().serialize(&mut sink)?;
    }
    Ok(())
}

fn adopt(config: Config, command: KeyAdoptCommand) -> Result<()> {
    let input = open_or_stdin(command.certificate.as_deref())?;
    let cert = Cert::from_reader(input)?;
    let mut wanted: Vec<(KeyHandle,
                         Option<(Key<key::PublicParts, key::SubordinateRole>,
                                 SignatureBuilder)>)>
        = vec![];

    // Gather the Key IDs / Fingerprints and make sure they are valid.
    for id in command.key {
        let h = id.parse::<KeyHandle>()?;
        if h.is_invalid() {
            return Err(anyhow::anyhow!(
                "Invalid Fingerprint or KeyID ('{:?}')", id));
        }
        wanted.push((h, None));
    }

    let null_policy = &crate::openpgp::policy::NullPolicy::new();
    let adoptee_policy: &dyn Policy =
        if command.allow_broken_crypto {
            null_policy
        } else {
            &config.policy
        };

    // Find the corresponding keys.
    for keyring in command.keyring {
        for cert in CertParser::from_file(&keyring)
            .context(format!("Parsing: {}", &keyring))?
        {
            let cert = cert.context(format!("Parsing {}", keyring))?;

            let vc = match cert.with_policy(adoptee_policy, None) {
                Ok(vc) => vc,
                Err(err) => {
                    eprintln!("Ignoring {} from '{}': {}",
                              cert.keyid().to_hex(), keyring, err);
                    continue;
                }
            };

            for key in vc.keys() {
                for (id, ref mut keyo) in wanted.iter_mut() {
                    if id.aliases(key.key_handle()) {
                        match keyo {
                            Some((_, _)) =>
                                // We already saw this key.
                                (),
                            None => {
                                let sig = key.binding_signature();
                                let builder: SignatureBuilder = match sig.typ() {
                                    SignatureType::SubkeyBinding =>
                                        sig.clone().into(),
                                    SignatureType::DirectKey
                                        | SignatureType::PositiveCertification
                                        | SignatureType::CasualCertification
                                        | SignatureType::PersonaCertification
                                        | SignatureType::GenericCertification =>
                                    {
                                        // Convert to a binding
                                        // signature.
                                        let kf = sig.key_flags()
                                            .context("Missing required \
                                                      subpacket, KeyFlags")?;
                                        SignatureBuilder::new(
                                            SignatureType::SubkeyBinding)
                                            .set_key_flags(kf)?
                                    },
                                    _ => panic!("Unsupported binding \
                                                 signature: {:?}",
                                                sig),
                                };

                                *keyo = Some(
                                    (key.key().clone().role_into_subordinate(),
                                     builder));
                            }
                        }
                    }
                }
            }
        }
    }


    // If we are missing any keys, stop now.
    let missing: Vec<&KeyHandle> = wanted
        .iter()
        .filter_map(|(id, keyo)| {
            match keyo {
                Some(_) => None,
                None => Some(id),
            }
        })
        .collect();
    if !missing.is_empty() {
        return Err(anyhow::anyhow!(
            "Keys not found: {}",
            missing.iter().map(|&h| h.to_hex()).join(", ")));
    }


    let passwords = &mut Vec::new();

    // Get a signer.
    let pk = cert.primary_key().key();
    let mut pk_signer =
        decrypt_key(
            pk.clone().parts_into_secret()?,
            passwords)?
        .into_keypair()?;


    // Add the keys and signatues to cert.
    let mut packets: Vec<Packet> = vec![];
    for (_, ka) in wanted.into_iter() {
        let (key, builder) = ka.expect("Checked for missing keys above.");
        let mut builder = builder;

        // If there is a valid backsig, recreate it.
        let need_backsig = builder.key_flags()
            .map(|kf| kf.for_signing() || kf.for_certification())
            .expect("Missing keyflags");

        if need_backsig {
            // Derive a signer.
            let mut subkey_signer
                = decrypt_key(
                    key.clone().parts_into_secret()?,
                    passwords)?
                .into_keypair()?;

            let backsig = builder.embedded_signatures()
                .find(|backsig| {
                    (*backsig).clone().verify_primary_key_binding(
                        &cert.primary_key(),
                        &key).is_ok()
                })
                .map(|sig| SignatureBuilder::from(sig.clone()))
                .unwrap_or_else(|| {
                    SignatureBuilder::new(SignatureType::PrimaryKeyBinding)
                })
                .sign_primary_key_binding(&mut subkey_signer, pk, &key)?;

            builder = builder.set_embedded_signature(backsig)?;
        } else {
            builder = builder.modify_hashed_area(|mut a| {
                a.remove_all(SubpacketTag::EmbeddedSignature);
                Ok(a)
            })?;
        }

        let mut sig = builder.sign_subkey_binding(&mut pk_signer, pk, &key)?;

        // Verify it.
        assert!(sig.verify_subkey_binding(pk_signer.public(), pk, &key)
                .is_ok());

        packets.push(key.into());
        packets.push(sig.into());
    }

    let cert = cert.clone().insert_packets(packets.clone())?;

    let mut sink = config.create_or_stdout_safe(command.output.as_deref())?;
    if command.binary {
        cert.as_tsk().serialize(&mut sink)?;
    } else {
        cert.as_tsk().armored().serialize(&mut sink)?;
    }

    let vc = cert.with_policy(&config.policy, None).expect("still valid");
    for pair in packets[..].chunks(2) {
        let newkey: &Key<key::PublicParts, key::UnspecifiedRole> = match pair[0] {
            Packet::PublicKey(ref k) => k.into(),
            Packet::PublicSubkey(ref k) => k.into(),
            Packet::SecretKey(ref k) => k.into(),
            Packet::SecretSubkey(ref k) => k.into(),
            ref p => panic!("Expected a key, got: {:?}", p),
        };
        let newsig: &Signature = match pair[1] {
            Packet::Signature(ref s) => s,
            ref p => panic!("Expected a sig, got: {:?}", p),
        };

        let mut found = false;
        for key in vc.keys() {
            if key.fingerprint() == newkey.fingerprint() {
                for sig in key.self_signatures() {
                    if sig == newsig {
                        found = true;
                        break;
                    }
                }
            }
        }
        assert!(found, "Subkey: {:?}\nSignature: {:?}", newkey, newsig);
    }

    Ok(())
}

fn attest_certifications(config: Config, command: KeyAttestCertificationsCommand)
                         -> Result<()> {
    // Attest to all certifications?
    let all = !command.none; // All is the default.

    let input = open_or_stdin(command.key.as_deref())?;
    let key = Cert::from_reader(input)?;

    // Get a signer.
    let mut passwords = Vec::new();
    let pk = key.primary_key().key();
    let mut pk_signer =
        decrypt_key(
            pk.clone().parts_into_secret()?,
            &mut passwords)?
        .into_keypair()?;

    // Now, create new attestation signatures.
    let mut attestation_signatures = Vec::new();
    for uid in key.userids() {
        if all {
            attestation_signatures.append(
                &mut uid.attest_certifications(&config.policy,
                                               &mut pk_signer,
                                               uid.certifications())?);
        } else {
            attestation_signatures.append(
                &mut uid.attest_certifications(&config.policy,
                                               &mut pk_signer, &[])?);
        }
    }

    for ua in key.user_attributes() {
        if all {
            attestation_signatures.append(
                &mut ua.attest_certifications(&config.policy,
                                              &mut pk_signer,
                                              ua.certifications())?);
        } else {
            attestation_signatures.append(
                &mut ua.attest_certifications(&config.policy,
                                              &mut pk_signer, &[])?);
        }
    }

    // Finally, add the new signatures.
    let key = key.insert_packets(attestation_signatures)?;

    let mut sink = config.create_or_stdout_safe(command.output.as_deref())?;
    if command.binary {
        key.as_tsk().serialize(&mut sink)?;
    } else {
        key.as_tsk().armored().serialize(&mut sink)?;
    }

    Ok(())
}
