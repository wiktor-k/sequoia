use clap::Parser;

use super::IoArgs;

#[derive(Parser, Debug)]
#[clap(
    name = "dearmor",
    about = "Converts ASCII to binary",
    long_about =
"Converts ASCII to binary

To make encrypted data easier to handle and transport, OpenPGP data
can be transformed to an ASCII representation called ASCII Armor.  sq
transparently handles armored data, but this subcommand can be used to
explicitly convert existing ASCII-encoded OpenPGP data to its binary
representation.

The converse operation is \"sq armor\".
",
    after_help =
"EXAMPLES:

# Convert a ASCII certificate to binary
$ sq dearmor ascii-juliet.pgp

# Convert a ASCII message to binary
$ sq dearmor ascii-message.pgp
",
    )]
pub struct Command {
    #[clap(flatten)]
    pub io: IoArgs,
}
