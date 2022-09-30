use clap::{Args, Parser, Subcommand};

use crate::sq_cli::types::{ArmorKind, IoArgs, SessionKey};

#[derive(Parser, Debug)]
#[clap(
    name = "packet",
    about = "Low-level packet manipulation",
    long_about =
"Low-level packet manipulation

An OpenPGP data stream consists of packets.  These tools allow working
with packet streams.  They are mostly of interest to developers, but
\"sq packet dump\" may be helpful to a wider audience both to provide
valuable information in bug reports to OpenPGP-related software, and
as a learning tool.
",
    subcommand_required = true,
    arg_required_else_help = true,
    setting(clap::AppSettings::DeriveDisplayOrder),
    )]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Dump(DumpCommand),
    Decrypt(DecryptCommand),
    Split(SplitCommand),
    Join(JoinCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Lists packets",
    long_about =
"Lists packets

Creates a human-readable description of the packet sequence.
Additionally, it can print cryptographic artifacts, and print the raw
octet stream similar to hexdump(1), annotating specifically which
bytes are parsed into OpenPGP values.

To inspect encrypted messages, either supply the session key, or see
\"sq decrypt --dump\" or \"sq packet decrypt\".
",
    after_help =
"EXAMPLES:

# Prints the packets of a certificate
$ sq packet dump juliet.pgp

# Prints cryptographic artifacts of a certificate
$ sq packet dump --mpis juliet.pgp

# Prints a hexdump of a certificate
$ sq packet dump --hex juliet.pgp

# Prints the packets of an encrypted message
$ sq packet dump --session-key AAAABBBBCCCC... ciphertext.pgp
",
)]
pub struct DumpCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        long = "session-key",
        value_name = "SESSION-KEY",
        help = "Decrypts an encrypted message using SESSION-KEY",
    )]
    pub session_key: Option<SessionKey>,
    #[clap(
        long = "mpis",
        help = "Prints cryptographic artifacts",
    )]
    pub mpis: bool,
    #[clap(
        short = 'x',
        long = "hex",
        help = "Prints a hexdump",
    )]
    pub hex: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Unwraps an encryption container",
    long_about = "Unwraps an encryption container

Decrypts a message, dumping the content of the encryption container
without further processing.  The result is a valid OpenPGP message
that can, among other things, be inspected using \"sq packet dump\".
",
    after_help =
"EXAMPLES:

# Unwraps the encryption revealing the signed message
$ sq packet decrypt --recipient-key juliet.pgp ciphertext.pgp
",
)]
pub struct DecryptCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        long = "recipient-key",
        value_name = "KEY_FILE",
        help = "Decrypts the message using the key in KEY_FILE",
    )]
    pub secret_key_file: Vec<String>,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        long = "session-key",
        value_name = "SESSION-KEY",
        help = "Decrypts an encrypted message using SESSION-KEY",
    )]
    pub session_key: Vec<SessionKey>,
    #[clap(
            long = "dump-session-key",
            help = "Prints the session key to stderr",
    )]
    pub dump_session_key: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Splits a message into packets",
    long_about = "Splits a message into packets

Splitting a packet sequence into individual packets, then recombining
them freely with \"sq packet join\" is a great way to experiment with
OpenPGP data.

The converse operation is \"sq packet join\".
",
    after_help =
"EXAMPLES:

# Split a certificate into individual packets
$ sq packet split juliet.pgp
",
)]
pub struct SplitCommand {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Option<String>,
    #[clap(
        short = 'p',
        long = "prefix",
        value_name = "PREFIX",
        help = "Writes to files with PREFIX \
            [defaults: \"FILE-\" if FILE is set, or \"output-\" if read from stdin]",
    )]
    pub prefix: Option<String>,
}

#[derive(Debug, Args)]
#[clap(
    about = "Joins packets split across files",
    long_about = "Joins packets split across files

Splitting a packet sequence into individual packets, then recombining
them freely with \"sq packet join\" is a great way to experiment with
OpenPGP data.

The converse operation is \"sq packet split\".
",
    after_help =
"EXAMPLES:

# Split a certificate into individual packets
$ sq packet split juliet.pgp

# Then join only a subset of these packets
$ sq packet join juliet.pgp-[0-3]*
",
)]
pub struct JoinCommand {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Vec<String>,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
    #[clap(
        long = "label",
        value_name = "LABEL",
        default_value_t = ArmorKind::Auto,
        conflicts_with = "binary",
        help = "Selects the kind of armor header",
        arg_enum,
    )]
    pub kind: ArmorKind,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}
