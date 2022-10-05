use clap::{ArgEnum, Parser};

use crate::sq_cli::types::{IoArgs, Time};

#[derive(Parser, Debug)]
#[clap(
    name = "encrypt",
    about = "Encrypts a message",
    long_about =
"Encrypts a message

Encrypts a message for any number of recipients and with any number of
passwords, optionally signing the message in the process.

The converse operation is \"sq decrypt\".
",
    after_help =
"EXAMPLES:

# Encrypt a file using a certificate
$ sq encrypt --recipient-file romeo.pgp message.txt

# Encrypt a file creating a signature in the process
$ sq encrypt --recipient-file romeo.pgp --signer-file juliet.pgp message.txt

# Encrypt a file using a password
$ sq encrypt --symmetric message.txt
",
)]
pub struct Command {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        long = "recipient-file",
        value_name = "CERT_RING_FILE",
        multiple_occurrences = true,
        help = "Encrypts to all certificates in CERT_RING_FILE",
    )]
    pub recipients_cert_file: Vec<String>,
    #[clap(
        long = "signer-file",
        value_name = "KEY_FILE",
        help = "Signs the message using the key in KEY_FILE",
    )]
    pub signer_key_file: Vec<String>,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        short = 's',
        long = "symmetric",
        help = "Adds a password to encrypt with",
        multiple_occurrences = true,
        long_help = "Adds a password to encrypt with.  \
            The message can be decrypted with \
            either one of the recipient's keys, or any password.",
        parse(from_occurrences)
    )]
    pub symmetric: usize,
    #[clap(
        long = "mode",
        value_name = "MODE",
        default_value_t = EncryptionMode::All,
        help = "Selects what kind of keys are considered for encryption.",
        long_help =
            "Selects what kind of keys are considered for \
            encryption.  Transport select subkeys marked \
            as suitable for transport encryption, rest \
            selects those for encrypting data at rest, \
            and all selects all encryption-capable \
            subkeys.",
        arg_enum,
    )]
    pub mode: EncryptionMode,
    #[clap(
        long = "compression",
        value_name = "KIND",
        default_value_t = CompressionMode::Pad,
        help = "Selects compression scheme to use",
        arg_enum,
    )]
    pub compression: CompressionMode,
    #[clap(
        short = 't',
        long = "time",
        value_name = "TIME",
        help = "Chooses keys valid at the specified time and \
            sets the signature's creation time",
    )]
    pub time: Option<Time>,
    #[clap(
        long = "use-expired-subkey",
        help = "Falls back to expired encryption subkeys",
        long_help =
            "If a certificate has only expired \
            encryption-capable subkeys, falls back \
            to using the one that expired last",
    )]
    pub use_expired_subkey: bool,
}

#[derive(ArgEnum, Debug, Clone)]
pub enum EncryptionMode {
    Transport,
    Rest,
    All
}

#[derive(ArgEnum, Debug, Clone)]
pub enum CompressionMode {
    None,
    Pad,
    Zip,
    Zlib,
    Bzip2
}
