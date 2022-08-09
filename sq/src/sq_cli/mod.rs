/// Command-line parser for sq.
use clap::{Command, CommandFactory, Parser, Subcommand};

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

pub mod types;

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
    setting(clap::AppSettings::DeriveDisplayOrder)
)]
pub struct SqCommand {
    #[clap(
        short = 'f',
        long = "force",
        help = "Overwrites existing files"
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
