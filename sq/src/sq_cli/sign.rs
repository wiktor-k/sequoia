use clap::Parser;

use crate::sq_cli::types::{IoArgs, Time};

#[derive(Parser, Debug)]
#[clap(
    name = "sign",
    about = "Signs messages or data files",
    long_about =
"Signs messages or data files

Creates signed messages or detached signatures.  Detached signatures
are often used to sign software packages.

The converse operation is \"sq verify\".
",
    after_help =
"EXAMPLES:

# Create a signed message
$ sq sign --signer-key juliet.pgp message.txt

# Create a detached signature
$ sq sign --detached --signer-key juliet.pgp message.txt
",
    )]
pub struct Command {
    #[clap(flatten)]
    pub io: IoArgs,
    // TODO: Why capital B?
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        long,
        help = "Creates a detached signature",
    )]
    pub detached: bool,
    #[clap(
        long = "cleartext-signature",
        help = "Creates a cleartext signature",
        conflicts_with_all = &[
            "detached",
            "append",
            "notarize",
            "binary",
        ],
    )]
    pub clearsign: bool,
    #[clap(
        short,
        long,
        conflicts_with = "notarize",
        help = "Appends a signature to existing signature",
    )]
    pub append: bool,
    #[clap(
        short,
        long,
        conflicts_with = "append",
        help = "Signs a message and all existing signatures",
    )]
    pub notarize: bool,
    #[clap(
        long,
        value_name = "SIGNED-MESSAGE",
        conflicts_with_all = &[
            "append",
            "detached",
            "clearsign",
            "notarize",
            "secret-key-file",
            "time",
        ],
        help = "Merges signatures from the input and SIGNED-MESSAGE",
    )]
    pub merge: Option<String>,
    #[clap(
        long = "signer-key",
        value_name = "KEY",
        help = "Signs using KEY",
    )]
    pub secret_key_file: Vec<String>,
    #[clap(
        short,
        long,
        value_name = "TIME",
        help = "Chooses keys valid at the specified time and sets the \
            signature's creation time",
    )]
    pub time: Option<Time>,
    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Adds a notation to the certification.",
        conflicts_with = "merge",
        long_help = "Adds a notation to the certification.  \
            A user-defined notation's name must be of the form \
            \"name@a.domain.you.control.org\". If the notation's name starts \
            with a !, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    // TODO: Is there a better way to express that one notation consists of two arguments, and
    // there may be multiple notations? Like something like Vec<(String, String)>.
    // TODO: Also, no need for the Option
    pub notation: Option<Vec<String>>,
}
