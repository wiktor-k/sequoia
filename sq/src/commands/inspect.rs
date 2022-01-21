use std::convert::TryFrom;
use std::io::{self, Read};

use sequoia_openpgp as openpgp;
use crate::openpgp::{KeyHandle, Packet, Result};
use crate::openpgp::cert::prelude::*;
use openpgp::packet::{
    Signature,
    key::PublicParts,
};
use crate::openpgp::parse::{Parse, PacketParserResult};
use crate::openpgp::policy::Policy;
use crate::openpgp::packet::key::SecretKeyMaterial;

use super::dump::Convert;

use crate::SECONDS_IN_YEAR;
use crate::SECONDS_IN_DAY;

pub fn inspect(m: &clap::ArgMatches, policy: &dyn Policy, output: &mut dyn io::Write)
               -> Result<()> {
    let print_certifications = m.is_present("certifications");

    let input = m.value_of("input");
    let input_name = input.unwrap_or("-");
    write!(output, "{}: ", input_name)?;

    let mut type_called = false;  // Did we print the type yet?
    let mut encrypted = false;    // Is it an encrypted message?
    let mut packets = Vec::new(); // Accumulator for packets.
    let mut pkesks = Vec::new();  // Accumulator for PKESKs.
    let mut n_skesks = 0;         // Number of SKESKs.
    let mut sigs = Vec::new();    // Accumulator for signatures.
    let mut literal_prefix = Vec::new();

    let mut ppr =
        openpgp::parse::PacketParser::from_reader(crate::open_or_stdin(input)?)?;
    while let PacketParserResult::Some(mut pp) = ppr {
        match pp.packet {
            Packet::PublicKey(_) | Packet::SecretKey(_) => {
                if pp.possible_cert().is_err()
                    && pp.possible_keyring().is_ok()
                {
                    if ! type_called {
                        writeln!(output, "OpenPGP Keyring.")?;
                        writeln!(output)?;
                        type_called = true;
                    }
                    let pp = openpgp::PacketPile::from(
                        std::mem::take(&mut packets));
                    let cert = openpgp::Cert::try_from(pp)?;
                    inspect_cert(policy, output, &cert,
                                 print_certifications)?;
                }
            },
            Packet::Literal(_) => {
                pp.by_ref().take(40).read_to_end(&mut literal_prefix)?;
            },
            Packet::SEIP(_) | Packet::AED(_) => {
                encrypted = true;
            },
            _ => (),
        }

        let possible_keyring = pp.possible_keyring().is_ok();
        let (packet, ppr_) = pp.recurse()?;
        ppr = ppr_;

        match packet {
            Packet::PKESK(p) => pkesks.push(p),
            Packet::SKESK(_) => n_skesks += 1,
            Packet::Signature(s) => if possible_keyring {
                packets.push(Packet::Signature(s))
            } else {
                sigs.push(s)
            },
            _ => packets.push(packet),
        }
    }

    if let PacketParserResult::EOF(eof) = ppr {
        let is_message = eof.is_message();
        let is_cert = eof.is_cert();
        let is_keyring = eof.is_keyring();

        if is_message.is_ok() {
            writeln!(output, "{}OpenPGP Message.",
                     match (encrypted, ! sigs.is_empty()) {
                         (false, false) => "",
                         (false, true) => "Signed ",
                         (true, false) => "Encrypted ",
                         (true, true) => "Encrypted and signed ",
                     })?;
            writeln!(output)?;
            if n_skesks > 0 {
                writeln!(output, "      Passwords: {}", n_skesks)?;
            }
            for pkesk in pkesks.iter() {
                writeln!(output, "      Recipient: {}", pkesk.recipient())?;
            }
            inspect_signatures(output, &sigs)?;
            if ! literal_prefix.is_empty() {
                writeln!(output, "           Data: {:?}{}",
                         String::from_utf8_lossy(&literal_prefix),
                         if literal_prefix.len() == 40 { "..." } else { "" })?;
            }

        } else if is_cert.is_ok() || is_keyring.is_ok() {
            let pp = openpgp::PacketPile::from(packets);
            let cert = openpgp::Cert::try_from(pp)?;
            inspect_cert(policy, output, &cert,
                         print_certifications)?;
        } else if packets.is_empty() && ! sigs.is_empty() {
            writeln!(output, "Detached signature{}.",
                     if sigs.len() > 1 { "s" } else { "" })?;
            writeln!(output)?;
            inspect_signatures(output, &sigs)?;
        } else if packets.is_empty() {
            writeln!(output, "No OpenPGP data.")?;
        } else {
            writeln!(output, "Unknown sequence of OpenPGP packets.")?;
            writeln!(output, "  Message: {}", is_message.unwrap_err())?;
            writeln!(output, "  Cert: {}", is_cert.unwrap_err())?;
            writeln!(output, "  Keyring: {}", is_keyring.unwrap_err())?;
            writeln!(output)?;
            writeln!(output, "Hint: Try 'sq packet dump {}'", input_name)?;
        }
    } else {
        unreachable!()
    }

    Ok(())
}

fn inspect_cert(policy: &dyn Policy,
                output: &mut dyn io::Write, cert: &openpgp::Cert,
                print_certifications: bool) -> Result<()> {
    if cert.is_tsk() {
        writeln!(output, "Transferable Secret Key.")?;
    } else {
        writeln!(output, "OpenPGP Certificate.")?;
    }
    writeln!(output)?;
    writeln!(output, "    Fingerprint: {}", cert.fingerprint())?;
    inspect_revocation(output, "", cert.revocation_status(policy, None))?;
    inspect_key(policy, output, "", cert.keys().next().unwrap(),
                print_certifications)?;
    writeln!(output)?;

    for vka in cert.keys().subkeys().with_policy(policy, None) {
        writeln!(output, "         Subkey: {}", vka.key().fingerprint())?;
        inspect_revocation(output, "", vka.revocation_status())?;
        inspect_key(policy, output, "", vka.into_key_amalgamation().into(),
                    print_certifications)?;
        writeln!(output)?;
    }

    fn print_error_chain(output: &mut dyn io::Write, err: &anyhow::Error)
                         -> Result<()> {
        writeln!(output, "                 Invalid: {}", err)?;
        for cause in err.chain().skip(1) {
            writeln!(output, "                 because: {}", cause)?;
        }
        Ok(())
    }

    for uidb in cert.userids() {
        writeln!(output, "         UserID: {}", uidb.userid())?;
        inspect_revocation(output, "", uidb.revocation_status(policy, None))?;
        match uidb.binding_signature(policy, None) {
            Ok(sig) => if let Err(e) =
                sig.signature_alive(None, std::time::Duration::new(0, 0))
            {
                print_error_chain(output, &e)?;
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_certifications(output,
                               uidb.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    for uab in cert.user_attributes() {
        writeln!(output, "         User attribute: {:?}",
                 uab.user_attribute())?;
        inspect_revocation(output, "", uab.revocation_status(policy, None))?;
        match uab.binding_signature(policy, None) {
            Ok(sig) => if let Err(e) =
                sig.signature_alive(None, std::time::Duration::new(0, 0))
            {
                print_error_chain(output, &e)?;
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_certifications(output,
                               uab.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    for ub in cert.unknowns() {
        writeln!(output, "         Unknown component: {:?}", ub.unknown())?;
        match ub.binding_signature(policy, None) {
            Ok(sig) => if let Err(e) =
                sig.signature_alive(None, std::time::Duration::new(0, 0))
            {
                print_error_chain(output, &e)?;
            }
            Err(e) => print_error_chain(output, &e)?,
        }
        inspect_certifications(output,
                               ub.certifications(),
                               print_certifications)?;
        writeln!(output)?;
    }

    for bad in cert.bad_signatures() {
        writeln!(output, "             Bad Signature: {:?}", bad)?;
    }

    Ok(())
}

fn inspect_key(policy: &dyn Policy,
               output: &mut dyn io::Write,
               indent: &str,
               ka: ErasedKeyAmalgamation<PublicParts>,
               print_certifications: bool)
        -> Result<()>
{
    let key = ka.key();
    let bundle = ka.bundle();
    let vka = match ka.with_policy(policy, None) {
        Ok(vka) => {
            if let Err(e) = vka.alive() {
                writeln!(output, "{}                 Invalid: {}", indent, e)?;
            }
            Some(vka)
        },
        Err(e) => {
            writeln!(output, "{}                 Invalid: {}", indent, e)?;
            None
        },
    };

    writeln!(output, "{}Public-key algo: {}", indent, key.pk_algo())?;
    if let Some(bits) = key.mpis().bits() {
        writeln!(output, "{}Public-key size: {} bits", indent, bits)?;
    }
    if let Some(secret) = key.optional_secret() {
        writeln!(output, "{}     Secret key: {}",
                 indent,
                 if let SecretKeyMaterial::Unencrypted(_) = secret {
                     "Unencrypted"
                 } else {
                     "Encrypted"
                 })?;
    }
    writeln!(output, "{}  Creation time: {}", indent,
             key.creation_time().convert())?;
    if let Some(vka) = vka {
        if let Some(expires) = vka.key_validity_period() {
            let expiration_time = key.creation_time() + expires;
            writeln!(output, "{}Expiration time: {} (creation time + {})",
                     indent,
                     expiration_time.convert(),
                     expires.convert())?;
        }

        if let Some(flags) = vka.key_flags().and_then(inspect_key_flags) {
            writeln!(output, "{}      Key flags: {}", indent, flags)?;
        }
    }
    inspect_certifications(output, bundle.certifications().iter(),
                           print_certifications)?;

    Ok(())
}

fn inspect_revocation(output: &mut dyn io::Write,
                      indent: &str,
                      revoked: openpgp::types::RevocationStatus)
                      -> Result<()> {
    use crate::openpgp::types::RevocationStatus::*;
    fn print_reasons(output: &mut dyn io::Write, indent: &str,
                     third_party: bool, sigs: &[&Signature])
                     -> Result<()> {
        for sig in sigs {
            if let Some((r, msg)) = sig.reason_for_revocation() {
                writeln!(output, "{}                  - {}", indent, r)?;
                if third_party {
                    writeln!(output, "{}                    Issued by {}",
                             indent,
                             if let Some(issuer)
                                 = sig.get_issuers().into_iter().next()
                             {
                                 issuer.to_string()
                             } else {
                                 "an unknown certificate".into()
                             })?;
                }
                writeln!(output, "{}                    Message: {:?}",
                         indent, String::from_utf8_lossy(msg))?;
            } else {
                writeln!(output, "{}                  - No reason specified",
                         indent)?;
                if third_party {
                    writeln!(output, "{}                    Issued by {}",
                             indent,
                             if let Some(issuer)
                                 = &sig.get_issuers().into_iter().next()
                             {
                                 issuer.to_string()
                             } else {
                                 "an unknown certificate".into()
                             })?;
                }
            }
        }
        Ok(())
    }
    match revoked {
        Revoked(sigs) => {
            writeln!(output, "{}                 Revoked:", indent)?;
            print_reasons(output, indent, false, &sigs)?;
        },
        CouldBe(sigs) => {
            writeln!(output, "{}                 Possibly revoked:", indent)?;
            print_reasons(output, indent, true, &sigs)?;
        },
        NotAsFarAsWeKnow => (),
    }

    Ok(())
}

fn inspect_key_flags(flags: openpgp::types::KeyFlags) -> Option<String> {
    let mut capabilities = Vec::new();
    if flags.for_certification() {
        capabilities.push("certification")
    }
    if flags.for_signing() {
        capabilities.push("signing")
    }
    if flags.for_authentication() {
        capabilities.push("authentication")
    }
    if flags.for_transport_encryption() {
        capabilities.push("transport encryption")
    }
    if flags.for_storage_encryption() {
        capabilities.push("data-at-rest encryption")
    }
    if flags.is_group_key() {
        capabilities.push("group key")
    }
    if flags.is_split_key() {
        capabilities.push("split key")
    }

    if !capabilities.is_empty() {
        Some(capabilities.join(", "))
    } else {
        None
    }
}

fn inspect_signatures(output: &mut dyn io::Write,
                      sigs: &[openpgp::packet::Signature]) -> Result<()> {
    use crate::openpgp::types::SignatureType::*;
    for sig in sigs {
        match sig.typ() {
            Binary | Text => (),
            signature_type =>
                writeln!(output, "           Kind: {}", signature_type)?,
        }

        let mut fps: Vec<_> = sig.issuer_fingerprints().collect();
        fps.sort();
        fps.dedup();
        let fps: Vec<KeyHandle> = fps.into_iter().map(|fp| fp.into()).collect();
        for fp in fps.iter() {
            writeln!(output, " Alleged signer: {}", fp)?;
        }
        let mut keyids: Vec<_> = sig.issuers().collect();
        keyids.sort();
        keyids.dedup();
        for keyid in keyids {
            if ! fps.iter().any(|fp| fp.aliases(&keyid.into())) {
                writeln!(output, " Alleged signer: {}", keyid)?;
            }
        }
    }
    if ! sigs.is_empty() {
        writeln!(output, "           Note: \
                          Signatures have NOT been verified!")?;
    }

    Ok(())
}

fn inspect_certifications<'a, A>(output: &mut dyn io::Write,
                          certs: A,
                          print_certifications: bool) -> Result<()> where
        A: std::iter::Iterator<Item=&'a openpgp::packet::Signature> {
    if print_certifications {
        let mut emit_warning = false;
        for sig in certs {
            let time = if let Some(time) = sig.signature_creation_time() {
                chrono::DateTime::<chrono::offset::Utc>::from(time)
            } else {
                // A signature must have a signature creation time
                // subpacket to be valid.  This signature is not
                // valid, so skip it.
                continue;
            };

            emit_warning = true;

            writeln!(output, "  Certification: Creation time: {}", time)?;

            let indent = "                 ";

            if let Some(e) = sig.signature_expiration_time() {
                let e = chrono::DateTime::<chrono::offset::Utc>::from(e);
                let diff = e - time;
                let years = diff.num_seconds() / (SECONDS_IN_YEAR as i64);
                let rest = diff.num_seconds() - years * (SECONDS_IN_YEAR as i64);
                let days = rest / (SECONDS_IN_DAY as i64);
                let rest = rest - days * (SECONDS_IN_DAY as i64);

                writeln!(output, "{}Expiration time: {} (after {}{}{}{}{})",
                         indent,
                         e,
                         match years {
                             0 => "".into(),
                             1 => format!("{} year", years),
                             _ => format!("{} years", years),
                         },
                         if years != 0 && days != 0 { ", " } else { "" },
                         match days {
                             0 => "".into(),
                             1 => format!("{} day", days),
                             _ => format!("{} days", days),
                         },
                         if years == 0 && days != 0 && rest != 0 { ", " } else { "" },
                         if years == 0 {
                             match rest {
                                 0 => "".into(),
                                 1 => format!("{} second", rest),
                                 _ => format!("{} seconds", rest),
                             }
                         } else {
                             "".into()
                         })?;
            }

            if let Some((depth, amount)) = sig.trust_signature() {
                writeln!(output, "{}Trust depth: {}", indent,
                         depth)?;
                writeln!(output, "{}Trust amount: {}", indent,
                         amount)?;
            }
            for re in sig.regular_expressions() {
                if let Ok(re) = String::from_utf8(re.to_vec()) {
                    writeln!(output, "{}Regular expression: {:?}", indent,
                             re)?;
                } else {
                    writeln!(output,
                             "{}Regular expression (invalid UTF-8): {:?}",
                             indent,
                             String::from_utf8_lossy(re))?;
                }
            }

            let mut fps: Vec<_> = sig.issuer_fingerprints().collect();
            fps.sort();
            fps.dedup();
            let fps: Vec<KeyHandle> = fps.into_iter().map(|fp| fp.into()).collect();
            for fp in fps.iter() {
                writeln!(output, "{}Alleged certifier: {}", indent, fp)?;
            }
            let mut keyids: Vec<_> = sig.issuers().collect();
            keyids.sort();
            keyids.dedup();
            for keyid in keyids {
                if ! fps.iter().any(|fp| fp.aliases(&keyid.into())) {
                    writeln!(output, "{}Alleged certifier: {}", indent,
                             keyid)?;
                }
            }
        }
        if emit_warning {
            writeln!(output, "           Note: \
                              Certifications have NOT been verified!")?;
        }
    } else {
        let count = certs.count();
        if count > 0 {
            writeln!(output, " Certifications: {}, \
                              use --certifications to list", count)?;
        }
    }

    Ok(())
}
