/// Command-line parser for sq.
use clap::{Command, ArgEnum, Args, Subcommand};
use clap::{CommandFactory, Parser};

use sequoia_openpgp as openpgp;
use openpgp::armor::Kind as OpenPGPArmorKind;
use openpgp::crypto::SessionKey as OpenPGPSessionKey;
use openpgp::types::SymmetricAlgorithm;
use openpgp::fmt::hex;

#[cfg(feature = "autocrypt")]
pub mod autocrypt;

pub mod armor;
pub mod certify;
mod dearmor;
mod decrypt;
pub mod encrypt;
pub mod inspect;
pub mod key;
pub mod keyring;
pub mod keyserver;
mod output_versions;
pub mod packet;
pub mod revoke;
mod sign;
mod verify;
pub mod wkd;

pub fn build() -> Command<'static> {
    let sq_version = Box::leak(
        format!(
            "{} (sequoia-openpgp {}, using {})",
            env!("CARGO_PKG_VERSION"),
            sequoia_openpgp::VERSION,
            sequoia_openpgp::crypto::backend()
        )
        .into_boxed_str(),
    ) as &str;
    SqCommand::command().version(sq_version)
}

/// Defines the CLI.
#[derive(Parser, Debug)]
#[clap(
    name = "sq",
    about = "A command-line frontend for Sequoia, an implementation of OpenPGP",
    long_about = "A command-line frontend for Sequoia, an implementation of OpenPGP

Functionality is grouped and available using subcommands.  Currently,
this interface is completely stateless.  Therefore, you need to supply
all configuration and certificates explicitly on each invocation.

OpenPGP data can be provided in binary or ASCII armored form.  This
will be handled automatically.  Emitted OpenPGP data is ASCII armored
by default.

We use the term \"certificate\", or cert for short, to refer to OpenPGP
keys that do not contain secrets.  Conversely, we use the term \"key\"
to refer to OpenPGP keys that do contain secrets.
",
    subcommand_required = true,
    arg_required_else_help = true,
    disable_colored_help = true,
    setting(clap::AppSettings::DeriveDisplayOrder),
)]
pub struct SqCommand {
    #[clap(
        short = 'f',
        long = "force",
        help = "Overwrites existing files",
    )]
    pub force: bool,
    #[clap(
        long = "output-format",
        value_name = "FORMAT",
        possible_values = ["human-readable", "json"],
        default_value = "human-readable",
        env = "SQ_OUTPUT_FORMAT",
        help = "Produces output in FORMAT, if possible",
    )]
    pub output_format: String,
    #[clap(
        long = "output-version",
        value_name = "VERSION",
        env = "SQ_OUTPUT_VERSION",
        help = "Produces output variant VERSION.",
        long_help = "Produces output variant VERSION, such as 0.0.0. \
                     The default is the newest version. The output version \
                     is separate from the version of the sq program. To see \
                     the current supported versions, use output-versions \
                     subcommand."
    )]
    pub output_version: Option<String>,
    #[clap(
        long = "known-notation",
        value_name = "NOTATION",
        multiple_occurrences = true,
        help = "Adds NOTATION to the list of known notations",
        long_help = "Adds NOTATION to the list of known notations. \
            This is used when validating signatures. \
            Signatures that have unknown notations with the \
            critical bit set are considered invalid."
    )]
    // TODO is this the right type?
    pub known_notation: Vec<String>,
    #[clap(subcommand)]
    pub subcommand: SqSubcommands,
}

/// The order of top-level subcommands is:
///
///   - Encryption & decryption
///   - Signing & verification
///   - Key & cert-ring management
///   - Key discovery & networking
///   - Armor
///   - Inspection & packet manipulation
///
/// The order is derived from the order of variants in this enum.
#[derive(Debug, Subcommand)]
pub enum SqSubcommands {
    Encrypt(encrypt::Command),
    Decrypt(decrypt::Command),

    Sign(sign::Command),
    Verify(verify::Command),

    Key(key::Command),
    Keyring(keyring::Command),
    Certify(certify::Command),

    #[cfg(feature = "autocrypt")]
    Autocrypt(autocrypt::Command),
    Keyserver(keyserver::Command),
    Wkd(wkd::Command),

    Armor(armor::Command),
    Dearmor(dearmor::Command),

    Inspect(inspect::Command),
    Packet(packet::Command),

    Revoke(revoke::Command),

    OutputVersions(output_versions::Command),
}

use chrono::{offset::Utc, DateTime};
#[derive(Debug)]
pub struct Time {
    pub time: DateTime<Utc>,
}

impl std::str::FromStr for Time {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Time> {
        let time =
            Time::parse_iso8601(s, chrono::NaiveTime::from_hms(0, 0, 0))?;
        Ok(Time { time })
    }
}

impl Time {
    /// Parses the given string depicting a ISO 8601 timestamp.
    fn parse_iso8601(
        s: &str,
        pad_date_with: chrono::NaiveTime,
    ) -> anyhow::Result<DateTime<Utc>> {
        // If you modify this function this function, synchronize the
        // changes with the copy in sqv.rs!
        for f in &[
            "%Y-%m-%dT%H:%M:%S%#z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M%#z",
            "%Y-%m-%dT%H:%M",
            "%Y-%m-%dT%H%#z",
            "%Y-%m-%dT%H",
            "%Y%m%dT%H%M%S%#z",
            "%Y%m%dT%H%M%S",
            "%Y%m%dT%H%M%#z",
            "%Y%m%dT%H%M",
            "%Y%m%dT%H%#z",
            "%Y%m%dT%H",
        ] {
            if f.ends_with("%#z") {
                if let Ok(d) = DateTime::parse_from_str(s, *f) {
                    return Ok(d.into());
                }
            } else if let Ok(d) = chrono::NaiveDateTime::parse_from_str(s, *f) {
                return Ok(DateTime::from_utc(d, Utc));
            }
        }
        for f in &[
            "%Y-%m-%d",
            "%Y-%m",
            "%Y-%j",
            "%Y%m%d",
            "%Y%m",
            "%Y%j",
            "%Y",
        ] {
            if let Ok(d) = chrono::NaiveDate::parse_from_str(s, *f) {
                return Ok(DateTime::from_utc(d.and_time(pad_date_with), Utc));
            }
        }
        Err(anyhow::anyhow!("Malformed ISO8601 timestamp: {}", s))
    }
}

#[derive(Debug, Args)]
pub struct IoArgs {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Option<String>,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
}

#[derive(ArgEnum, Debug, Clone)]
pub enum ArmorKind {
    Auto,
    Message,
    #[clap(name = "cert")]
    PublicKey,
    #[clap(name = "key")]
    SecretKey,
    #[clap(name = "sig")]
    Signature,
    File,
}

impl From<ArmorKind> for Option<OpenPGPArmorKind> {

    fn from(c: ArmorKind) -> Self {
        match c {
            ArmorKind::Auto => None,
            ArmorKind::Message => Some(OpenPGPArmorKind::Message),
            ArmorKind::PublicKey => Some(OpenPGPArmorKind::PublicKey),
            ArmorKind::SecretKey => Some(OpenPGPArmorKind::SecretKey),
            ArmorKind::Signature => Some(OpenPGPArmorKind::Signature),
            ArmorKind::File => Some(OpenPGPArmorKind::File),
        }
    }
}

#[derive(ArgEnum, Clone, Debug)]
pub enum NetworkPolicy {
    Offline,
    Anonymized,
    Encrypted,
    Insecure,
}

impl From<NetworkPolicy> for sequoia_net::Policy {
    fn from(kp: NetworkPolicy) -> Self {
        match kp {
            NetworkPolicy::Offline => sequoia_net::Policy::Offline,
            NetworkPolicy::Anonymized => sequoia_net::Policy::Anonymized,
            NetworkPolicy::Encrypted => sequoia_net::Policy::Encrypted,
            NetworkPolicy::Insecure => sequoia_net::Policy::Insecure,
        }
    }
}

/// Holds a session key as parsed from the command line, with an optional
/// algorithm specifier.
///
/// This struct does not implement [`Display`] to prevent accidental leaking
/// of key material. If you are sure you want to print a session key, use
/// [`display_sensitive`].
///
/// [`Display`]: std::fmt::Display
/// [`display_sensitive`]: CliSessionKey::display_sensitive
#[derive(Debug, Clone)]
pub struct SessionKey {
    pub session_key: OpenPGPSessionKey,
    pub symmetric_algo: Option<SymmetricAlgorithm>,
}

impl std::str::FromStr for SessionKey {
    type Err = anyhow::Error;

    /// Parse a session key. The format is: an optional prefix specifying the
    /// symmetric algorithm as a number, followed by a colon, followed by the
    /// session key in hexadecimal representation.
    fn from_str(sk: &str) -> anyhow::Result<Self> {
        let result = if let Some((algo, sk)) = sk.split_once(':') {
            let algo = SymmetricAlgorithm::from(algo.parse::<u8>()?);
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: Some(algo),
            }
        } else {
            let dsk = hex::decode_pretty(sk)?.into();
            SessionKey {
                session_key: dsk,
                symmetric_algo: None,
            }
        };
        Ok(result)
    }
}

impl SessionKey {

    /// Returns an object that implements Display for explicitly opting into
    /// printing a `SessionKey`.
    pub fn display_sensitive(&self) -> SessionKeyDisplay {
        SessionKeyDisplay { csk: self }
    }
}

/// Helper struct for intentionally printing session keys with format! and {}.
///
/// This struct implements the `Display` trait to print the session key. This
/// construct requires the user to explicitly call
/// [`CliSessionKey::display_sensitive`]. By requiring the user to opt-in, this
/// will hopefully reduce that the chance that the session key is inadvertently
/// leaked, e.g., in a log that may be publicly posted.
pub struct SessionKeyDisplay<'a> {
    csk: &'a SessionKey,
}

/// Print the session key without prefix in hexadecimal representation.
impl<'a> std::fmt::Display for SessionKeyDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let sk = self.csk;
        write!(f, "{}", hex::encode(&sk.session_key))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_iso8601() -> anyhow::Result<()> {
        let z = chrono::NaiveTime::from_hms(0, 0, 0);
        Time::parse_iso8601("2017-03-04T13:25:35Z", z)?;
        Time::parse_iso8601("2017-03-04T13:25:35+08:30", z)?;
        Time::parse_iso8601("2017-03-04T13:25:35", z)?;
        Time::parse_iso8601("2017-03-04T13:25Z", z)?;
        Time::parse_iso8601("2017-03-04T13:25", z)?;
        // CliTime::parse_iso8601("2017-03-04T13Z", z)?; // XXX: chrono doesn't like
        // CliTime::parse_iso8601("2017-03-04T13", z)?; // ditto
        Time::parse_iso8601("2017-03-04", z)?;
        // CliTime::parse_iso8601("2017-03", z)?; // ditto
        Time::parse_iso8601("2017-031", z)?;
        Time::parse_iso8601("20170304T132535Z", z)?;
        Time::parse_iso8601("20170304T132535+0830", z)?;
        Time::parse_iso8601("20170304T132535", z)?;
        Time::parse_iso8601("20170304T1325Z", z)?;
        Time::parse_iso8601("20170304T1325", z)?;
        // CliTime::parse_iso8601("20170304T13Z", z)?; // ditto
        // CliTime::parse_iso8601("20170304T13", z)?; // ditto
        Time::parse_iso8601("20170304", z)?;
        // CliTime::parse_iso8601("201703", z)?; // ditto
        Time::parse_iso8601("2017031", z)?;
        // CliTime::parse_iso8601("2017", z)?; // ditto
        Ok(())
    }
}
