use clap::{ArgEnum, Parser};

use super::IoArgs;

// TODO?: Option<_> conflicts with default value
// TODO: Use PathBuf as input type for more type safety? Investigate conversion
// TODO: use indoc to transparently (de-)indent static strings
#[derive(Parser, Debug)]
#[clap(
    name = "armor",
    about = "Converts binary to ASCII",
    long_about =
"Converts binary to ASCII

To make encrypted data easier to handle and transport, OpenPGP data
can be transformed to an ASCII representation called ASCII Armor.  sq
emits armored data by default, but this subcommand can be used to
convert existing OpenPGP data to its ASCII-encoded representation.

The converse operation is \"sq dearmor\".
",
    after_help =
"EXAMPLES:

# Convert a binary certificate to ASCII
$ sq armor binary-juliet.pgp

# Convert a binary message to ASCII
$ sq armor binary-message.pgp
"
    )]
pub struct Command {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        long = "label",
        value_name = "LABEL",
        help = "Selects the kind of armor header",
        default_value_t = ArmorKind::Auto,
        arg_enum
    )]
    pub kind: ArmorKind,
}

#[derive(ArgEnum)]
#[derive(Debug, Clone)]
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

use sequoia_openpgp::armor::Kind as OpenPGPArmorKind;
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
