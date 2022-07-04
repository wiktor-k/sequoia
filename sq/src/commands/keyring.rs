use std::{
    collections::HashMap,
    collections::hash_map::Entry,
    fs::File,
    io,
    path::PathBuf,
};
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    armor,
    cert::{
        Cert,
        CertParser,
    },
    Fingerprint,
    KeyHandle,
    packet::{
        UserID,
        UserAttribute,
        Key,
    },
    parse::Parse,
    serialize::Serialize,
};

use crate::{
    Config,
    open_or_stdin,
};

use crate::sq_cli::KeyringCommand;
use crate::sq_cli::KeyringSubcommands::*;

pub fn dispatch(config: Config, c: KeyringCommand) -> Result<()> {
    match c.subcommand {
        Filter(command) => {
            let any_uid_predicates =
                command.userid.is_some()
                || command.name.is_some()
                || command.email.is_some()
                || command.domain.is_some();
            let uid_predicate = |uid: &UserID| {
                let mut keep = false;

                if let Some(userids) = &command.userid {
                    for userid in userids {
                        keep |= uid.value() == userid.as_bytes();
                    }
                }

                if let Some(names) = &command.name {
                    for name in names {
                        keep |= uid
                            .name().unwrap_or(None)
                            .map(|n| &n == name)
                            .unwrap_or(false);
                    }
                }

                if let Some(emails) = &command.email {
                    for email in emails {
                        keep |= uid
                            .email().unwrap_or(None)
                            .map(|n| &n == email)
                            .unwrap_or(false);
                    }
                }

                if let Some(domains) = &command.domain {
                    for domain in domains {
                        keep |= uid
                            .email().unwrap_or(None)
                            .map(|n| n.ends_with(&format!("@{}", domain)))
                            .unwrap_or(false);
                    }
                }

                keep
            };

            let any_ua_predicates = false;
            let ua_predicate = |_ua: &UserAttribute| false;

            let any_key_predicates = command.handle.is_some();
            let handles: Vec<KeyHandle> =
                if let Some(handles) = &command.handle {
                    use std::str::FromStr;
                    handles.iter().map(|h| KeyHandle::from_str(h))
                        .collect::<Result<_>>()?
                } else {
                    Vec::with_capacity(0)
                };
            let key_predicate = |key: &Key<_, _>| {
                let mut keep = false;

                for handle in &handles {
                    keep |= handle.aliases(key.key_handle());
                }

                keep
            };

            let filter_fn = |c: Cert| -> Option<Cert> {
                if ! (any_uid_predicates
                      || any_ua_predicates
                      || any_key_predicates) {
                    // If there are no filters, pass it through.
                    Some(c)
                } else if ! (c.userids().any(|c| uid_predicate(&c))
                             || c.user_attributes().any(|c| ua_predicate(&c))
                             || c.keys().any(|c| key_predicate(c.key()))) {
                    None
                } else if command.prune_certs {
                    let c = c
                        .retain_userids(|c| {
                            ! any_uid_predicates || uid_predicate(&c)
                        })
                        .retain_user_attributes(|c| {
                            ! any_ua_predicates || ua_predicate(&c)
                        })
                        .retain_subkeys(|c| {
                            ! any_key_predicates
                                || key_predicate(c.key().role_as_unspecified())
                        });
                    if c.userids().count() == 0
                        && c.user_attributes().count() == 0
                        && c.keys().subkeys().count() == 0
                    {
                        // We stripped all components, omit this cert.
                        None
                    } else {
                        Some(c)
                    }
                } else {
                    Some(c)
                }
            };

            let to_certificate = command.to_certificate;

            // XXX: Armor type selection is a bit problematic.  If any
            // of the certificates contain a secret key, it would be
            // better to use Kind::SecretKey here.  However, this
            // requires buffering all certs, which has its own
            // problems.
            let mut output =
                config.create_or_stdout_pgp(command.output.as_deref(),
                                            command.binary,
                                            armor::Kind::PublicKey)?;
            filter(&command.input, &mut output, filter_fn, to_certificate)?;
            output.finalize()
        },
        Join(c) => {
            // XXX: Armor type selection is a bit problematic.  If any
            // of the certificates contain a secret key, it would be
            // better to use Kind::SecretKey here.  However, this
            // requires buffering all certs, which has its own
            // problems.
            let mut output =
                config.create_or_stdout_pgp(c.output.as_deref(),
                                            c.binary,
                                            armor::Kind::PublicKey)?;
            filter(&c.input, &mut output, Some, false)?;
            output.finalize()
        },
        Merge(c) => {
            let mut output =
                config.create_or_stdout_pgp(c.output.as_deref(),
                                            c.binary,
                                            armor::Kind::PublicKey)?;
            merge(c.input, &mut output)?;
            output.finalize()
        },
        List(c) => {
            let mut input = open_or_stdin(c.input.as_deref())?;
            list(config, &mut input, c.all_userids)
        },
        Split(c) => {
            let mut input = open_or_stdin(c.input.as_deref())?;
            let prefix =
            // The prefix is either specified explicitly...
                c.prefix.unwrap_or(
                    // ... or we derive it from the input file...
                    c.input.and_then(|i| {
                        let p = PathBuf::from(i);
                        // (but only use the filename)
                        p.file_name().map(|f| String::from(f.to_string_lossy()))
                    })
                    // ... or we use a generic prefix...
                        .unwrap_or_else(|| String::from("output"))
                    // ... finally, add a hyphen to the derived prefix.
                        + "-");
            split(&mut input, &prefix, c.binary)
        },
    }
}

/// Joins certificates and keyrings into a keyring, applying a filter.
fn filter<F>(inputs: &[String], output: &mut dyn io::Write,
             mut filter: F, to_certificate: bool)
             -> Result<()>
    where F: FnMut(Cert) -> Option<Cert>,
{
    if !inputs.is_empty() {
        for name in inputs {
            for cert in CertParser::from_file(name)? {
                let cert = cert.context(
                    format!("Malformed certificate in keyring {:?}", name))?;
                if let Some(cert) = filter(cert) {
                    if to_certificate {
                        cert.serialize(output)?;
                    } else {
                        cert.as_tsk().serialize(output)?;
                    }
                }
            }
        }
    } else {
        for cert in CertParser::from_reader(io::stdin())? {
            let cert = cert.context("Malformed certificate in keyring")?;
            if let Some(cert) = filter(cert) {
                if to_certificate {
                    cert.serialize(output)?;
                } else {
                    cert.as_tsk().serialize(output)?;
                }
            }
        }
    }
    Ok(())
}

/// Lists certs in a keyring.
fn list(config: Config,
        input: &mut (dyn io::Read + Sync + Send),
        list_all_uids: bool)
        -> Result<()>
{
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let cert = match cert {
            Ok(cert) => cert,
            Err(e) => {
                println!("{}. {}", i, e);
                continue;
            },
        };
        let line = format!("{}. {:X}", i, cert.fingerprint());
        let indent = line.chars().map(|_| ' ').collect::<String>();
        print!("{}", line);

        // Try to be more helpful by including a User ID in the
        // listing.  We'd like it to be the primary one.  Use
        // decreasingly strict policies.
        let mut primary_uid = None;

        // First, apply our policy.
        if let Ok(vcert) = cert.with_policy(&config.policy, None) {
            if let Ok(primary) = vcert.primary_userid() {
                println!(" {}", String::from_utf8_lossy(primary.value()));
                primary_uid = Some(primary.value().to_vec());
            }
        }

        // Second, apply the null policy.
        if primary_uid.is_none() {
            let null = openpgp::policy::NullPolicy::new();
            if let Ok(vcert) = cert.with_policy(&null, None) {
                if let Ok(primary) = vcert.primary_userid() {
                    println!(" {}", String::from_utf8_lossy(primary.value()));
                    primary_uid = Some(primary.value().to_vec());
                }
            }
        }

        // As a last resort, pick the first user id.
        if primary_uid.is_none() {
            if let Some(primary) = cert.userids().next() {
                println!(" {}", String::from_utf8_lossy(primary.value()));
                primary_uid = Some(primary.value().to_vec());
            }
        }

        if primary_uid.is_none() {
            // No dice.
            println!();
        }

        if list_all_uids {
            // List all user ids independently of their validity.
            for u in cert.userids() {
                if primary_uid.as_ref()
                    .map(|p| &p[..] == u.value()).unwrap_or(false)
                {
                    // Skip the user id we already printed.
                    continue;
                }

                println!("{} {}", indent,
                         String::from_utf8_lossy(u.value()));
            }
        }
    }
    Ok(())
}

/// Splits a keyring into individual certs.
fn split(input: &mut (dyn io::Read + Sync + Send), prefix: &str, binary: bool)
         -> Result<()> {
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let (filename, cert) = match cert {
            Ok(cert) => {
                let filename = format!(
                    "{}{}-{:X}",
                    prefix,
                    i,
                    cert.fingerprint());
                (filename, Ok(cert))
            },
            Err(mut e) => if let Some(openpgp::Error::UnsupportedCert2(m, p)) =
                e.downcast_mut::<openpgp::Error>()
            {
                // We didn't understand the cert.  But, we can still
                // write it out!
                let filename = format!(
                    "{}{}-{}",
                    prefix,
                    i,
                    to_filename_fragment(m).unwrap_or_else(|| "unknown".to_string()));
                (filename, Err(std::mem::take(p)))
            } else {
                return Err(e.context("Malformed certificate in keyring"));
            },
        };

        // Try to be more helpful by including the first userid in the
        // filename.
        let mut sink = if let Some(f) = cert.as_ref().ok()
            .and_then(|cert| cert.userids().next())
            .and_then(|uid| uid.email().unwrap_or(None))
            .and_then(to_filename_fragment)
        {
            let filename_email = format!("{}-{}", filename, f);
            if let Ok(s) = File::create(filename_email) {
                s
            } else {
                // Degrade gracefully in case our sanitization
                // produced an invalid filename on this system.
                File::create(&filename)
                    .context(format!("Writing cert to {:?} failed", filename))?
            }
        } else {
            File::create(&filename)
                .context(format!("Writing cert to {:?} failed", filename))?
        };

        if binary {
            match cert {
                Ok(cert) => cert.as_tsk().serialize(&mut sink)?,
                Err(packets) => for p in packets {
                    p.serialize(&mut sink)?;
                },
            }
        } else {
            use sequoia_openpgp::serialize::stream::{Message, Armorer};
            let message = Message::new(sink);
            let mut message = Armorer::new(message)
            // XXX: should detect kind, see above
                .kind(sequoia_openpgp::armor::Kind::PublicKey)
                .build()?;
            match cert {
                Ok(cert) => cert.as_tsk().serialize(&mut message)?,
                Err(packets) => for p in packets {
                    p.serialize(&mut message)?;
                },
            }
            message.finalize()?;
        }
    }
    Ok(())
}

/// Merge multiple keyrings.
fn merge(inputs: Vec<String>, output: &mut dyn io::Write)
             -> Result<()>
{
    let mut certs: HashMap<Fingerprint, Option<Cert>> = HashMap::new();

    if !inputs.is_empty() {
        for name in inputs {
            for cert in CertParser::from_file(&name)? {
                let cert = cert.context(
                    format!("Malformed certificate in keyring {:?}", name))?;
                match certs.entry(cert.fingerprint()) {
                    e @ Entry::Vacant(_) => {
                        e.or_insert(Some(cert));
                    }
                    Entry::Occupied(mut e) => {
                        let e = e.get_mut();
                        let curr = e.take().unwrap();
                        *e = Some(curr.merge_public_and_secret(cert)
                            .expect("Same certificate"));
                    }
                }
            }
        }
    } else {
        for cert in CertParser::from_reader(io::stdin())? {
            let cert = cert.context("Malformed certificate in keyring")?;
            match certs.entry(cert.fingerprint()) {
                e @ Entry::Vacant(_) => {
                    e.or_insert(Some(cert));
                }
                Entry::Occupied(mut e) => {
                    let e = e.get_mut();
                    let curr = e.take().unwrap();
                    *e = Some(curr.merge_public_and_secret(cert)
                              .expect("Same certificate"));
                }
            }
        }
    }

    let mut fingerprints: Vec<Fingerprint> = certs.keys().cloned().collect();
    fingerprints.sort();

    for fpr in fingerprints.iter() {
        if let Some(Some(cert)) = certs.get(fpr) {
            cert.as_tsk().serialize(output)?;
        }
    }

    Ok(())
}

/// Sanitizes a string to a safe filename fragment.
fn to_filename_fragment<S: AsRef<str>>(s: S) -> Option<String> {
    let mut r = String::with_capacity(s.as_ref().len());

    s.as_ref().chars().filter_map(|c| match c {
        '/' | ':' | '\\' => None,
        c if c.is_ascii_whitespace() => None,
        c if c.is_ascii() => Some(c),
        _ => None,
    }).for_each(|c| r.push(c));

    if !r.is_empty() {
        Some(r)
    } else {
        None
    }
}
