use clap::Parser;

use crate::sq_cli::types::{IoArgs, SessionKey};

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
$ sq decrypt --recipient-file juliet.pgp ciphertext.pgp

# Decrypt a file verifying signatures
$ sq decrypt --recipient-file juliet.pgp --signer-cert romeo.pgp ciphertext.pgp

# Decrypt a file using a password
$ sq decrypt ciphertext.pgp
",
)]
// TODO use usize
pub struct Command {
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
        value_name = "CERT_FILE",
        help = "Verifies signatures using the certificates in CERT_FILE",
    )]
    pub sender_cert_file: Vec<String>,
    #[clap(
        long = "recipient-file",
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
            long = "dump-session-key",
            help = "Prints the session key to stderr",
    )]
    pub dump_session_key: bool,
    #[clap(
        long = "session-key",
        value_name = "SESSION-KEY",
        help = "Decrypts an encrypted message using SESSION-KEY",
    )]
    pub session_key: Vec<SessionKey>,
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
