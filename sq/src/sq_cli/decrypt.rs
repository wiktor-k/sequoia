use clap::Parser;

use super::{CliSessionKey, IoArgs};

#[derive(Parser, Debug)]
#[clap(
    name = "decrypt",
    about = "Decrypts a message",
    long_about =
"Decrypts a message

Decrypts a message using either supplied keys, or by prompting for a
password.  If message tampering is detected, an error is returned.
See below for details.

If certificates are supplied using the \"--signer-cert\" option, any
signatures that are found are checked using these certificates.
Verification is only successful if there is no bad signature, and the
number of successfully verified signatures reaches the threshold
configured with the \"--signatures\" parameter.

If the signature verification fails, or if message tampering is
detected, the program terminates with an exit status indicating
failure.  In addition to that, the last 25 MiB of the message are
withheld, i.e. if the message is smaller than 25 MiB, no output is
produced, and if it is larger, then the output will be truncated.

The converse operation is \"sq encrypt\".
",
    after_help =
"EXAMPLES:

# Decrypt a file using a secret key
$ sq decrypt --recipient-key juliet.pgp ciphertext.pgp

# Decrypt a file verifying signatures
$ sq decrypt --recipient-key juliet.pgp --signer-cert romeo.pgp ciphertext.pgp

# Decrypt a file using a password
$ sq decrypt ciphertext.pgp
",
)]
// TODO use usize
pub struct DecryptCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        short = 'n',
        long = "signatures",
        value_name = "N",
        help = "Sets the threshold of valid signatures to N",
        long_help =
            "Sets the threshold of valid signatures to N. \
            The message will only be considered \
            verified if this threshold is reached. \
            [default: 1 if at least one signer cert file \
                              is given, 0 otherwise]",
    )]
    pub signatures: Option<usize>,
    #[clap(
        long = "signer-cert",
        value_name = "CERT",
        help = "Verifies signatures with CERT",
    )]
    pub sender_cert_file: Vec<String>,
    #[clap(
        long = "recipient-key",
        value_name = "KEY",
        help = "Decrypts with KEY",
    )]
    pub secret_key_file: Vec<String>,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
            long = "dump-session-key",
            help = "Prints the session key to stderr",
    )]
    pub dump_session_key: bool,
    #[clap(
        long = "session-key",
        value_name = "SESSION-KEY",
        help = "Decrypts an encrypted message using SESSION-KEY",
    )]
    pub session_key: Vec<CliSessionKey>,
    #[clap(
        long = "dump",
        help = "Prints a packet dump to stderr",
    )]
    pub dump: bool,
    #[clap(
        short = 'x',
        long = "hex",
        help = "Prints a hexdump (implies --dump)",
    )]
    pub hex: bool,
}
