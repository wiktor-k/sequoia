/// Command-line parser for sq.
use clap::{ArgGroup, Command, ArgEnum, Args, Subcommand};
use clap::{CommandFactory, Parser};

use sequoia_openpgp as openpgp;
use openpgp::crypto::SessionKey;
use openpgp::types::SymmetricAlgorithm;
use openpgp::fmt::hex;

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
///
/// The order of top-level subcommands is:
///
///   - Encryption & decryption             (1xx)
///   - Signing & verification              (2xx)
///   - Key & cert-ring management          (3xx)
///   - Key discovery & networking          (4xx)
///   - Armor                               (5xx)
///   - Inspection & packet manipulation    (6xx)
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
)]
struct SqCommand {
    #[clap(
        short = 'f',
        long = "force",
        help = "Overwrites existing files",
    )]
    pub force: bool,
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

#[derive(Debug, Subcommand)]
pub enum SqSubcommands {
    Armor(ArmorCommand),
    Dearmor(DearmorCommand),
    Sign(SignCommand),
    Verify(VerifyCommand),
    Wkd(WkdCommand),
    Keyserver(KeyserverCommand),
    Revoke(RevokeCommand),
    Packet(PacketCommand),
    Certify(CertifyCommand),
    Keyring(KeyringCommand),
    Key(KeyCommand),
    Inspect(InspectCommand),
    Encrypt(EncryptCommand),
    Decrypt(DecryptCommand),
    #[cfg(feature = "autocrypt")]
    Autocrypt(autocrypt::AutocryptCommand),
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

// TODO?: Option<_> conflicts with default value
// TODO: Use PathBuf as input type for more type safety? Investigate conversion
// TODO: use indoc to transparently (de-)indent static strings
#[derive(Parser, Debug)]
#[clap(
    name = "armor",
    display_order = 500,
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
pub struct ArmorCommand {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Option<String>,
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
        help = "Selects the kind of armor header",
        default_value_t = CliArmorKind::Auto,
        arg_enum
    )]
    pub kind: CliArmorKind,
}

#[derive(ArgEnum)]
#[derive(Debug, Clone)]
pub enum CliArmorKind {
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
impl From<CliArmorKind> for Option<OpenPGPArmorKind> {
    fn from(c: CliArmorKind) -> Self {
        match c {
            CliArmorKind::Auto => None,
            CliArmorKind::Message => Some(OpenPGPArmorKind::Message),
            CliArmorKind::PublicKey => Some(OpenPGPArmorKind::PublicKey),
            CliArmorKind::SecretKey => Some(OpenPGPArmorKind::SecretKey),
            CliArmorKind::Signature => Some(OpenPGPArmorKind::Signature),
            CliArmorKind::File => Some(OpenPGPArmorKind::File),
        }
    }
}

#[derive(Parser, Debug)]
#[clap(name = "dearmor", display_order(510))]
#[clap(
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
pub struct DearmorCommand {
    #[clap(flatten)]
    pub io: IoArgs,
}

#[derive(Parser, Debug)]
#[clap(
    name = "verify",
    display_order(210),
    about = "Verifies signed messages or detached signatures",
    long_about = "Verifies signed messages or detached signatures

When verifying signed messages, the message is written to stdout or
the file given to --output.

When a detached message is verified, no output is produced.  Detached
signatures are often used to sign software packages.

Verification is only successful if there is no bad signature, and the
number of successfully verified signatures reaches the threshold
configured with the \"--signatures\" parameter.  If the verification
fails, the program terminates with an exit status indicating failure.
In addition to that, the last 25 MiB of the message are withheld,
i.e. if the message is smaller than 25 MiB, no output is produced, and
if it is larger, then the output will be truncated.

The converse operation is \"sq sign\".
",
    after_help =
"EXAMPLES:

# Verify a signed message
$ sq verify --signer-cert juliet.pgp signed-message.pgp

# Verify a detached message
$ sq verify --signer-cert juliet.pgp --detached message.sig message.txt

SEE ALSO:

If you are looking for a standalone program to verify detached
signatures, consider using sequoia-sqv.
",
    )]
pub struct VerifyCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        long = "detached",
        value_name = "SIG",
        help = "Verifies a detached signature"
    )]
    pub detached: Option<String>,
    #[clap(
        short = 'n',
        long = "signatures",
        value_name = "N",
        default_value_t = 1,
        help = "Sets the threshold of valid signatures to N",
        long_help = "Sets the threshold of valid signatures to N. \
                            If this threshold is not reached, the message \
                            will not be considered verified."
    )]
    pub signatures: usize,
    #[clap(
        long = "signer-cert",
        value_name = "CERT",
        help = "Verifies signatures with CERT",
    )]
    // TODO: Should at least one sender_cert_file be required? Verification does not make sense
    // without one, does it?
    // TODO Use PathBuf instead of String. Path representation is platform dependent, so Rust's
    // utf-8 Strings are not quite appropriate.
    // TODO: And adapt load_certs in sq.rs
    pub sender_cert_file: Vec<String>,
}

#[derive(Parser, Debug)]
#[clap(
    name = "sign",
    display_order(200),
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
pub struct SignCommand {
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
    //TODO: Fix type & parsing
    pub time: Option<String>,
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

#[derive(Parser, Debug)]
#[clap(
    name = "packet",
    display_order = 610,
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
    )]
pub struct PacketCommand {
    #[clap(subcommand)]
    pub subcommand: PacketSubcommands,
}

#[derive(Debug, Subcommand)]
pub enum PacketSubcommands {
    Dump(PacketDumpCommand),
    Decrypt(PacketDecryptCommand),
    Split(PacketSplitCommand),
    Join(PacketJoinCommand),
}

#[derive(Debug, Args)]
#[clap(
    display_order = 100,
    about = "Lists packets",
    long_about =
"
Lists packets

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
pub struct PacketDumpCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        long = "session-key",
        value_name = "SESSION-KEY",
        help = "Decrypts an encrypted message using SESSION-KEY",
    )]
    pub session_key: Option<CliSessionKey>,
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
    display_order = 200,
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
pub struct PacketDecryptCommand {
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
        value_name = "KEY",
        help = "Decrypts the message with KEY",
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
    pub session_key: Vec<CliSessionKey>,
    #[clap(
            long = "dump-session-key",
            help = "Prints the session key to stderr",
    )]
    pub dump_session_key: bool,
}

#[derive(Debug, Args)]
#[clap(
    display_order = 300,
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
pub struct PacketSplitCommand {
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
    display_order = 310,
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
pub struct PacketJoinCommand {
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
        default_value_t = PacketKind::Auto,
        conflicts_with = "binary",
        help = "Selects the kind of armor header",
        arg_enum,
    )]
    pub kind: PacketKind,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}
// TODO: reuse CliArmorKind, requires changes in sq.rs
#[derive(ArgEnum, Clone, Debug)]
pub enum PacketKind {
    Auto,
    Message,
    Cert,
    Key,
    Sig,
    File
}

#[derive(Parser, Debug)]
#[clap(
    name = "revoke",
    display_order = 700,
    about = "Generates revocation certificates",
    long_about = "Generates revocation certificates.

A revocation certificate indicates that a certificate, a subkey, a
User ID, or a signature should not be used anymore.

A revocation certificate includes two fields, a type and a
human-readable explanation, which allows the issuer to indicate why
the revocation certificate was issued.  It is important to set the
type field accurately as this allows an OpenPGP implementation to
better reason about artifacts whose validity relies on the revoked
object.  For instance, if a certificate is retired, it is reasonable
to consider signatures that it made prior to its retirement as still
being valid.  However, if a certificate's secret key material is
compromised, any signatures that it made should be considered
potentially forged, as they could have been made by an attacker and
backdated.

As the intent of a revocation certificate is to stop others from using
a certificate, it is necessary to distribute the revocation
certificate.  One effective way to do this is to upload the revocation
certificate to a keyserver.
",
    after_help =
"EXAMPLES:

# Revoke a certificate.
$ sq revoke certificate --time 20220101 --certificate juliet.pgp \\
  compromised \"My parents went through my things, and found my backup.\"

# Revoke a User ID.
$ sq revoke userid --time 20220101 --certificate juliet.pgp \\
  \"Juliet <juliet@capuleti.it>\" retired \"I've left the family.\"
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct RevokeCommand {
    #[clap(subcommand)]
    pub subcommand: RevokeSubcommands,
}

#[derive(Debug, Subcommand)]
pub enum RevokeSubcommands {
    Certificate(RevokeCertificateCommand),
    Subkey(RevokeSubkeyCommand),
    Userid(RevokeUseridCommand),
}

#[derive(Debug, Args)]
#[clap(
    display_order = 100,
    about = "Revoke a certificate",
    long_about =
"Revokes a certificate

Creates a revocation certificate for the certificate.

If \"--revocation-key\" is provided, then that key is used to create
the signature.  If that key is different from the certificate being
revoked, this creates a third-party revocation.  This is normally only
useful if the owner of the certificate designated the key to be a
designated revoker.

If \"--revocation-key\" is not provided, then the certificate must
include a certification-capable key.
",
)]
pub struct RevokeCertificateCommand {
    #[clap(
        value_name = "FILE",
        long = "certificate",
        alias = "cert",
        help = "The certificate to revoke",
        long_help =
"Reads the certificate to revoke from FILE or stdin, if omitted.  It is \
an error for the file to contain more than one certificate.",
    )]
    pub input: Option<String>,
    #[clap(
        long = "revocation-key",
        value_name = "KEY",
        help = "Signs the revocation certificate using KEY",
        long_help =
"Signs the revocation certificate using KEY.  If the key is different \
from the certificate, this creates a third-party revocation.  If this \
option is not provided, and the certificate includes secret key material, \
then that key is used to sign the revocation certificate.",
    )]
    pub secret_key_file: Option<String>,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,

    #[clap(
        value_name = "REASON",
        required = true,
        help = "The reason for the revocation",
        long_help =
"The reason for the revocation.  This must be either: compromised,
superseded, retired, or unspecified:

  - compromised means that the secret key material may have been
    compromised.  Prefer this value if you suspect that the secret
    key has been leaked.

  - superseded means that the owner of the certificate has replaced
    it with a new certificate.  Prefer \"compromised\" if the secret
    key material has been compromised even if the certificate is also
    being replaced!  You should include the fingerprint of the new
    certificate in the message.

  - retired means that this certificate should not be used anymore,
    and there is no replacement.  This is appropriate when someone
    leaves an organisation.  Prefer \"compromised\" if the secret key
    material has been compromised even if the certificate is also
    being retired!  You should include how to contact the owner, or
    who to contact instead in the message.

  - unspecified means that none of the three other three reasons
    apply.  OpenPGP implementations conservatively treat this type
    of revocation similar to a compromised key.

If the reason happened in the past, you should specify that using the
--time argument.  This allows OpenPGP implementations to more
accurately reason about objects whose validity depends on the validity
of the certificate.",
    arg_enum,
    )]
    pub reason: RevocationReason,

    #[clap(
        value_name = "MESSAGE",
        help = "A short, explanatory text",
        long_help =
"A short, explanatory text that is shown to a viewer of the revocation \
certificate.  It explains why the certificate has been revoked.  For \
instance, if Alice has created a new key, she would generate a \
'superseded' revocation certificate for her old key, and might include \
the message \"I've created a new certificate, FINGERPRINT, please use \
that in the future.\"",
    )]
    pub message: String,
    #[clap(
        short,
        long,
        value_name = "TIME",
        help =
"Chooses keys valid at the specified time and sets the revocation \
certificate's creation time",
    )]
    pub time: Option<String>,
    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Adds a notation to the certification.",
        long_help = "Adds a notation to the certification.  \
            A user-defined notation's name must be of the form \
            \"name@a.domain.you.control.org\". If the notation's name starts \
            with a !, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Option<Vec<String>>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(ArgEnum, Clone, Debug)]
pub enum RevocationReason {
    Compromised,
    Superseded,
    Retired,
    Unspecified
}

#[derive(Debug, Args)]
#[clap(
    display_order = 105,
    about = "Revoke a subkey",
    long_about =
"Revokes a subkey

Creates a revocation certificate for a subkey.

If \"--revocation-key\" is provided, then that key is used to create \
the signature.  If that key is different from the certificate being \
revoked, this creates a third-party revocation.  This is normally only \
useful if the owner of the certificate designated the key to be a \
designated revoker.

If \"--revocation-key\" is not provided, then the certificate must \
include a certification-capable key.",
)]
pub struct RevokeSubkeyCommand {
    #[clap(
        value_name = "FILE",
        long = "certificate",
        alias = "cert",
        help = "The certificate containing the subkey to revoke",
        long_help =
"Reads the certificate containing the subkey to revoke from FILE or stdin, \
if omitted.  It is an error for the file to contain more than one \
certificate."
    )]
    pub input: Option<String>,
    #[clap(
        long = "revocation-key",
        value_name = "KEY",
        help = "Signs the revocation certificate using KEY",
        long_help =
"Signs the revocation certificate using KEY.  If the key is different \
from the certificate, this creates a third-party revocation.  If this \
option is not provided, and the certificate includes secret key material, \
then that key is used to sign the revocation certificate.",
    )]
    pub secret_key_file: Option<String>,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        value_name = "SUBKEY",
        help = "The subkey to revoke",
        long_help =
"The subkey to revoke.  This must either be the subkey's Key ID or its \
fingerprint.",
    )]
    pub subkey: String,

    #[clap(
        value_name = "REASON",
        required = true,
        help = "The reason for the revocation",
        long_help =
"The reason for the revocation.  This must be either: compromised, \
superseded, retired, or unspecified:

  - compromised means that the secret key material may have been
    compromised.  Prefer this value if you suspect that the secret
    key has been leaked.

  - superseded means that the owner of the certificate has replaced
    it with a new certificate.  Prefer \"compromised\" if the secret
    key material has been compromised even if the certificate is
    also being replaced!  You should include the fingerprint of the
    new certificate in the message.

  - retired means that this certificate should not be used anymore,
    and there is no replacement.  This is appropriate when someone
    leaves an organisation.  Prefer \"compromised\" if the secret key
    material has been compromised even if the certificate is also
    being retired!  You should include how to contact the owner, or
    who to contact instead in the message.

  - unspecified means that none of the three other three reasons
    apply.  OpenPGP implementations conservatively treat this type
    of revocation similar to a compromised key.

If the reason happened in the past, you should specify that using the \
--time argument.  This allows OpenPGP implementations to more \
accurately reason about objects whose validity depends on the validity \
of the certificate.",
    arg_enum,
    )]
    pub reason: RevocationReason,
    #[clap(
        value_name = "MESSAGE",
        help = "A short, explanatory text",
        long_help =
"A short, explanatory text that is shown to a viewer of the revocation \
certificate.  It explains why the subkey has been revoked.  For \
instance, if Alice has created a new key, she would generate a \
'superseded' revocation certificate for her old key, and might include \
the message \"I've created a new subkey, please refresh the certificate."
    )]
    pub message: String,
    #[clap(
        short,
        long,
        value_name = "TIME",
        help =
"Chooses keys valid at the specified time and sets the revocation \
certificate's creation time",
    )]
    pub time: Option<String>,
    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Adds a notation to the certification.",
        long_help = "Adds a notation to the certification.  \
            A user-defined notation's name must be of the form \
            \"name@a.domain.you.control.org\". If the notation's name starts \
            with a !, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Option<Vec<String>>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    display_order = 110,
    about = "Revoke a User ID",
    long_about =
"Revokes a User ID

Creates a revocation certificate for a User ID.

If \"--revocation-key\" is provided, then that key is used to create \
the signature.  If that key is different from the certificate being \
revoked, this creates a third-party revocation.  This is normally only \
useful if the owner of the certificate designated the key to be a \
designated revoker.

If \"--revocation-key\" is not provided, then the certificate must \
include a certification-capable key.",
)]
pub struct RevokeUseridCommand {
    #[clap(
        value_name = "FILE",
        long = "certificate",
        alias = "cert",
        help = "The certificate containing the User ID to revoke",
        long_help =
"Reads the certificate to revoke from FILE or stdin, \
if omitted.  It is an error for the file to contain more than one \
certificate."
    )]
    pub input: Option<String>,
    #[clap(
        long = "revocation-key",
        value_name = "KEY",
        help = "Signs the revocation certificate using KEY",
        long_help =
"Signs the revocation certificate using KEY.  If the key is different \
from the certificate, this creates a third-party revocation.  If this \
option is not provided, and the certificate includes secret key material, \
then that key is used to sign the revocation certificate.",
    )]
    pub secret_key_file: Option<String>,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        value_name = "USERID",
        help = "The User ID to revoke",
        long_help =
"The User ID to revoke.  By default, this must exactly match a \
self-signed User ID.  Use --force to generate a revocation certificate \
for a User ID, which is not self signed."
    )]
    pub userid: String,
    #[clap(
        arg_enum,
        value_name = "REASON",
        help = "The reason for the revocation",
        long_help =
"The reason for the revocation.  This must be either: retired, or \
unspecified:

  - retired means that this User ID is no longer valid.  This is
    appropriate when someone leaves an organisation, and the
    organisation does not have their secret key material.  For
    instance, if someone was part of Debian and retires, they would
    use this to indicate that a Debian-specific User ID is no longer
    valid.

  - unspecified means that a different reason applies.

If the reason happened in the past, you should specify that using the \
--time argument.  This allows OpenPGP implementations to more \
accurately reason about objects whose validity depends on the validity \
of a User ID."
    )]
    pub reason: UseridRevocationReason,
    #[clap(
        value_name = "MESSAGE",
        help = "A short, explanatory text",
        long_help =
"A short, explanatory text that is shown to a viewer of the revocation \
certificate.  It explains why the certificate has been revoked.  For \
instance, if Alice has created a new key, she would generate a \
'superseded' revocation certificate for her old key, and might include \
the message \"I've created a new certificate, FINGERPRINT, please use \
that in the future.\"",
    )]
    pub message: String,
    #[clap(
        short,
        long,
        value_name = "TIME",
        help =
"Chooses keys valid at the specified time and sets the revocation \
certificate's creation time",
    )]
    pub time: Option<String>,
    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Adds a notation to the certification.",
        long_help = "Adds a notation to the certification.  \
            A user-defined notation's name must be of the form \
            \"name@a.domain.you.control.org\". If the notation's name starts \
            with a !, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Option<Vec<String>>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(ArgEnum, Clone, Debug)]
pub enum UseridRevocationReason {
    Retired,
    Unspecified
}

#[derive(Parser, Debug)]
#[clap(
    name = "certify",
    display_order = 320,
    about = "Certifies a User ID for a Certificate",
    long_about =
"Certifies a User ID for a Certificate

Using a certification a keyholder may vouch for the fact that another
certificate legitimately belongs to a user id.  In the context of
emails this means that the same entity controls the key and the email
address.  These kind of certifications form the basis for the Web Of
Trust.

This command emits the certificate with the new certification.  The
updated certificate has to be distributed, preferably by sending it to
the certificate holder for attestation.  See also \"sq key
attest-certification\".
",
    after_help =
"EXAMPLES:

# Juliet certifies that Romeo controls romeo.pgp and romeo@example.org
$ sq certify juliet.pgp romeo.pgp \"<romeo@example.org>\"
",
)]
#[clap(group(ArgGroup::new("expiration-group").args(&["expires", "expires-in"])))]
pub struct CertifyCommand {
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        long = "time",
        value_name = "TIME",
        help = "Sets the certification time to TIME (as ISO 8601)",
        long_help = "\
Sets the certification time to TIME.  TIME is interpreted as an ISO 8601
timestamp.  To set the certification time to June 9, 2011 at midnight UTC,
you can do:

$ sq certify --time 20130721 neal.pgp ada.pgp ada

To include a time, add a T, the time and optionally the timezone (the
default timezone is UTC):

$ sq certify --time 20130721T0550+0200 neal.pgp ada.pgp ada
",
    )]
    pub time: Option<String>,
    #[clap(
        short = 'd',
        long = "depth",
        value_name = "TRUST_DEPTH",
        help = "Sets the trust depth",
        long_help =
            "Sets the trust depth (sometimes referred to as the trust level).  \
            0 means a normal certification of <CERTIFICATE, USERID>.  \
            1 means CERTIFICATE is also a trusted introducer, 2 means \
            CERTIFICATE is a meta-trusted introducer, etc.  The default is 0.",
    )]
    //TODO: use usize, not String
    pub depth: Option<String>,
    #[clap(
        short = 'a',
        long = "amount",
        value_name = "TRUST_AMOUNT",
        help = "Sets the amount of trust",
        long_help =
            "Sets the amount of trust.  Values between 1 and 120 are meaningful. \
            120 means fully trusted.  Values less than 120 indicate the degree \
            of trust.  60 is usually used for partially \
            trusted.  The default is 120.",
    )]
    //TODO: use usize, not String
    pub amount: Option<String>,
    #[clap(
        short = 'r',
        long = "regex",
        value_name = "REGEX",
        help = "Adds a regular expression to constrain \
            what a trusted introducer can certify",
        long_help =
            "Adds a regular expression to constrain \
            what a trusted introducer can certify.  \
            The regular expression must match \
            the certified User ID in all intermediate \
            introducers, and the certified certificate. \
            Multiple regular expressions may be \
            specified.  In that case, at least \
            one must match.",
    )]
    pub regex: Vec<String>,
    #[clap(
        short = 'l',
        long = "local",
        help = "Makes the certification a local certification",
        long_help =
            "Makes the certification a local \
            certification.  Normally, local \
            certifications are not exported.",
    )]
    pub local: bool,
    #[clap(
        long = "non-revocable",
        help = "Marks the certification as being non-revocable",
        long_help =
            "Marks the certification as being non-revocable. \
            That is, you cannot later revoke this \
            certification.  This should normally only \
            be used with an expiration.",
    )]
    pub non_revocable: bool,
    #[clap(
        long,
        value_names = &["NAME", "VALUE"],
        number_of_values = 2,
        help = "Adds a notation to the certification.",
        long_help = "Adds a notation to the certification.  \
            A user-defined notation's name must be of the form \
            \"name@a.domain.you.control.org\". If the notation's name starts \
            with a !, then the notation is marked as being critical.  If a \
            consumer of a signature doesn't understand a critical notation, \
            then it will ignore the signature.  The notation is marked as \
            being human readable."
    )]
    pub notation: Option<Vec<String>>,
    #[clap(
        long = "expires",
        value_name = "TIME",
        help = "Makes the certification expire at TIME (as ISO 8601)",
        long_help =
            "Makes the certification expire at TIME (as ISO 8601). \
            Use \"never\" to create certifications that do not expire.",
    )]
    pub expires: Option<String>,
    #[clap(
        long = "expires-in",
        value_name = "DURATION",
        // Catch negative numbers.
        allow_hyphen_values = true,
        help = "Makes the certification expire after DURATION \
            (as N[ymwds]) [default: 5y]",
        long_help =
            "Makes the certification expire after DURATION. \
            Either \"N[ymwds]\", for N years, months, \
            weeks, days, seconds, or \"never\".  [default: 5y]",
    )]
    pub expires_in: Option<String>,
    #[clap(
        long = "allow-not-alive-certifier",
        help = "Don't fail if the certificate making the \
                certification is not alive.",
        long_help =
            "Allows the key to make a certification even if \
             the current time is prior to its creation time \
             or the current time is at or after its expiration \
             time.",
    )]
    pub allow_not_alive_certifier: bool,
    #[clap(
        long = "allow-revoked-certifier",
        help = "Don't fail if the certificate making the \
                certification is revoked.",
    )]
    pub allow_revoked_certifier: bool,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        value_name = "CERTIFIER-KEY",
        required = true,
        index = 1,
        help = "Creates the certification using CERTIFIER-KEY.",
    )]
    pub certifier: String,
    #[clap(
        value_name = "CERTIFICATE",
        required = true,
        index = 2,
        help = "Certifies CERTIFICATE.",
    )]
    pub certificate: String,
    #[clap(
        value_name = "USERID",
        required = true,
        index = 3,
        help = "Certifies USERID for CERTIFICATE.",
    )]
    pub userid: String,
}


#[derive(Parser, Debug)]
#[clap(
    name = "keyring",
    display_order = 310,
    about = "Manages collections of keys or certs",
    long_about =
"Manages collections of keys or certs

Collections of keys or certficicates (also known as \"keyrings\" when
they contain secret key material, and \"certrings\" when they don't) are
any number of concatenated certificates.  This subcommand provides
tools to list, split, join, merge, and filter keyrings.

Note: In the documentation of this subcommand, we sometimes use the
terms keys and certs interchangeably.
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct KeyringCommand {
    #[clap(subcommand)]
    pub subcommand: KeyringSubcommands,
}

#[derive(Debug, Subcommand)]
pub enum KeyringSubcommands {
    Filter(KeyringFilterCommand),
    Join(KeyringJoinCommand),
    Merge(KeyringMergeCommand),
    List(KeyringListCommand),
    Split(KeyringSplitCommand),
}

#[derive(Debug, Args)]
#[clap(
    display_order = 600,
    about = "Joins keys into a keyring applying a filter",
    long_about =
"Joins keys into a keyring applying a filter

This can be used to filter keys based on given predicates,
e.g. whether they have a user id containing an email address with a
certain domain.  Additionally, the keys can be pruned to only include
components matching the predicates.

If no filters are supplied, everything matches.

If multiple predicates are given, they are or'ed, i.e. a key matches
if any of the predicates match.  To require all predicates to match,
chain multiple invocations of this command.  See EXAMPLES for
inspiration.
",
    after_help =
"EXAMPLES:

# Converts a key to a cert (i.e., remove any secret key material)
$ sq keyring filter --to-cert cat juliet.pgp

# Gets the keys with a user id on example.org
$ sq keyring filter --domain example.org keys.pgp

# Gets the keys with a user id on example.org or example.net
$ sq keyring filter --domain example.org --domain example.net keys.pgp

# Gets the keys with a user id with the name Juliet
$ sq keyring filter --name Juliet keys.pgp

# Gets the keys with a user id with the name Juliet on example.org
$ sq keyring filter --domain example.org keys.pgp | \\
  sq keyring filter --name Juliet

# Gets the keys with a user id on example.org, pruning other userids
$ sq keyring filter --domain example.org --prune-certs certs.pgp
",
)]
pub struct KeyringFilterCommand {
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
        long = "userid",
        value_name = "USERID",
        multiple_occurrences = true,
        help = "Matches on USERID",
        long_help = "Case-sensitively matches on the \
                user id, requiring an exact match.",
    )]
    pub userid: Option<Vec<String>>,
    #[clap(
        long = "name",
        value_name = "NAME",
        multiple_occurrences = true,
        help = "Matches on NAME",
        long_help = "Parses user ids into name and email \
            and case-sensitively matches on the \
            name, requiring an exact match.",
    )]
    pub name: Option<Vec<String>>,
    #[clap(
        long = "email",
        value_name = "ADDRESS",
        multiple_occurrences = true,
        help = "Matches on email ADDRESS",
        long_help = "Parses user ids into name and email \
            address and case-sensitively matches \
            on the email address, requiring an exact match.",
    )]
    pub email: Option<Vec<String>>,
    #[clap(
        long = "domain",
        value_name = "FQDN",
        help = "Matches on email domain FQDN",
        long_help =
            "Parses user ids into name and email \
            address and case-sensitively matches \
            on the domain of the email address, \
            requiring an exact match.",
    )]
    pub domain: Option<Vec<String>>,
    #[clap(
        long = "handle",
        value_name = "FINGERPRINT|KEYID",
        help = "Matches on (sub)key fingerprints and key ids",
        long_help =
            "Matches on both primary keys and subkeys, \
            including those certificates that match the \
            given fingerprint or key id.",
    )]
    pub handle: Option<Vec<String>>,
    #[clap(
        short = 'P',
        long = "prune-certs",
        help = "Removes certificate components not matching the filter",
    )]
    pub prune_certs: bool,
    #[clap(
        short = 'B',
        long = "binary",
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        long = "to-cert",
        help = "Converts any keys in the input to \
            certificates.  Converting a key to a \
            certificate removes secret key material \
            from the key thereby turning it into \
            a certificate.",
    )]
    pub to_certificate: bool,
}

#[derive(Debug, Args)]
#[clap(
    display_order = 300,
    about = "Joins keys or keyrings into a single keyring",
    long_about =
"Joins keys or keyrings into a single keyring

Unlike \"sq keyring merge\", multiple versions of the same key are not
merged together.

The converse operation is \"sq keyring split\".
",
    after_help =
"EXAMPLES:

# Collect certs for an email conversation
$ sq keyring join juliet.pgp romeo.pgp alice.pgp
",
)]
pub struct KeyringJoinCommand {
    #[clap(value_name = "FILE", help = "Sets the input files to use")]
    pub input: Vec<String>,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Sets the output file to use"
    )]
    pub output: Option<String>,
    #[clap(
        short = 'B',
        long = "binary",
        help = "Don't ASCII-armor the keyring",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    display_order = 350,
    about = "Merges keys or keyrings into a single keyring",
    long_about =
"Merges keys or keyrings into a single keyring

Unlike \"sq keyring join\", the certificates are buffered and multiple
versions of the same certificate are merged together.  Where data is
replaced (e.g., secret key material), data from the later certificate
is preferred.
",
    after_help =
"EXAMPLES:

# Merge certificate updates
$ sq keyring merge certs.pgp romeo-updates.pgp
",
)]
pub struct KeyringMergeCommand {
    #[clap(
        value_name = "FILE",
        help = "Reads from FILE",
    )]
    pub input: Vec<String>,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
    #[clap(
        short = 'B',
        long = "binary",
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Lists keys in a keyring",
    display_order = 100,
    long_about =
"Lists keys in a keyring

Prints the fingerprint as well as the primary userid for every
certificate encountered in the keyring.
",
    after_help =
"EXAMPLES:

# List all certs
$ sq keyring list certs.pgp

# List all certs with a userid on example.org
$ sq keyring filter --domain example.org certs.pgp | sq keyring list
",
)]
pub struct KeyringListCommand {
    #[clap(
        value_name = "FILE",
        help = "Reads from FILE or stdin if omitted",
    )]
    pub input: Option<String>,
    #[clap(
        long = "--all-userids",
        help = "Lists all user ids",
        long_help = "Lists all user ids, even those that are \
            expired, revoked, or not valid under the \
            standard policy.",
    )]
    pub all_userids: bool,
}

#[derive(Debug, Args)]
#[clap(
    display_order = 200,
    about = "Splits a keyring into individual keys",
    long_about =
"Splits a keyring into individual keys

Splitting up a keyring into individual keys helps with curating a
keyring.

The converse operation is \"sq keyring join\".
",
    after_help =
"EXAMPLES:

# Split all certs
$ sq keyring split certs.pgp

# Split all certs, merging them first to avoid duplicates
$ sq keyring merge certs.pgp | sq keyring split
",
)]
pub struct KeyringSplitCommand {
    #[clap(
        value_name = "FILE",
        help = "Reads from FILE or stdin if omitted",
    )]
    pub input: Option<String>,
    #[clap(
        short = 'p',
        long = "prefix",
        value_name = "PREFIX",
        help = "Writes to files with PREFIX \
            [defaults: \"FILE-\" if FILE is set, or \"output-\" if read from stdin]",
    )]
    pub prefix: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Parser, Debug)]
#[clap(
    name = "key",
    display_order = 300,
    about = "Manages keys",
    long_about =
"Manages keys

We use the term \"key\" to refer to OpenPGP keys that do contain
secrets.  This subcommand provides primitives to generate and
otherwise manipulate keys.

Conversely, we use the term \"certificate\", or cert for short, to refer
to OpenPGP keys that do not contain secrets.  See \"sq keyring\" for
operations on certificates.
",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct KeyCommand {
    #[clap(subcommand)]
    pub subcommand: KeySubcommands,
}

#[derive(Debug, Subcommand)]
pub enum KeySubcommands {
    Generate(KeyGenerateCommand),
    Password(KeyPasswordCommand),
    ExtractCert(KeyExtractCertCommand),
    Adopt(KeyAdoptCommand),
    AttestCertifications(KeyAttestCertificationsCommand),
}

#[derive(Debug, Args)]
#[clap(
    display_order = 100,
    about = "Generates a new key",
    long_about =
"Generates a new key

Generating a key is the prerequisite to receiving encrypted messages
and creating signatures.  There are a few parameters to this process,
but we provide reasonable defaults for most users.

When generating a key, we also generate a revocation certificate.
This can be used in case the key is superseded, lost, or compromised.
It is a good idea to keep a copy of this in a safe place.

After generating a key, use \"sq key extract-cert\" to get the
certificate corresponding to the key.  The key must be kept secure,
while the certificate should be handed out to correspondents, e.g. by
uploading it to a keyserver.
",
    after_help =
"EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this extracts the certificate for distribution
$ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp

# Generates a key protecting it with a password
$ sq key generate --userid \"<juliet@example.org>\" --with-password

# Generates a key with multiple userids
$ sq key generate --userid \"<juliet@example.org>\" --userid \"Juliet Capulet\"
",
)]
#[clap(group(ArgGroup::new("expiration-group").args(&["expires", "expires-in"])))]
#[clap(group(ArgGroup::new("cap-sign").args(&["can-sign", "cannot-sign"])))]
#[clap(group(ArgGroup::new("cap-authenticate").args(&["can-authenticate", "cannot-authenticate"])))]
#[clap(group(ArgGroup::new("cap-encrypt").args(&["can-encrypt", "cannot-encrypt"])))]
pub struct KeyGenerateCommand {
    #[clap(
        short = 'u',
        long = "userid",
        value_name = "EMAIL",
        help = "Adds a userid to the key"
    )]
    pub userid: Option<Vec<String>>,
    #[clap(
        short = 'c',
        long = "cipher-suite",
        value_name = "CIPHER-SUITE",
        default_value_t = KeyCipherSuite::Cv25519,
        help = "Selects the cryptographic algorithms for the key",
        arg_enum,
    )]
    pub cipher_suite: KeyCipherSuite,
    #[clap(
        long = "with-password",
        help = "Protects the key with a password",
    )]
    pub with_password: bool,
    #[clap(
        long = "creation-time",
        value_name = "CREATION_TIME",
        help = "Sets the key's creation time to TIME (as ISO 8601)",
        long_help = "\
Sets the key's creation time to TIME.  TIME is interpreted as an ISO 8601
timestamp.  To set the creation time to June 9, 2011 at midnight UTC,
you can do:

$ sq key generate --creation-time 20110609 --export noam.pgp

To include a time, add a T, the time and optionally the timezone (the
default timezone is UTC):

$ sq key generate --creation-time 20110609T1938+0200 --export noam.pgp
",
    )]
    pub creation_time: Option<String>,
    #[clap(
        long = "expires",
        value_name = "TIME",
        help = "Makes the key expire at TIME (as ISO 8601)",
        long_help =
            "Makes the key expire at TIME (as ISO 8601). \
            Use \"never\" to create keys that do not expire.",
    )]
    // TODO: Use a wrapper type for CliTime
    pub expires: Option<String>,
    #[clap(
        long = "expires-in",
        value_name = "DURATION",
        // Catch negative numbers.
        allow_hyphen_values = true,
        help = "Makes the key expire after DURATION \
            (as N[ymwds]) [default: 5y]",
        long_help =
            "Makes the key expire after DURATION. \
            Either \"N[ymwds]\", for N years, months, \
            weeks, days, seconds, or \"never\".",
    )]
    pub expires_in: Option<String>,
    #[clap(
        long = "can-sign",
        help ="Adds a signing-capable subkey (default)",
    )]
    pub can_sign: bool,
    #[clap(
        long = "cannot-sign",
        help = "Adds no signing-capable subkey",
    )]
    pub cannot_sign: bool,
    #[clap(
        long = "can-authenticate",
        help = "Adds an authentication-capable subkey (default)",
    )]
    pub can_authenticate: bool,
    #[clap(
        long = "cannot-authenticate",
        help = "Adds no authentication-capable subkey",
    )]
    pub cannot_authenticate: bool,
    #[clap(
        long = "can-encrypt",
        value_name = "PURPOSE",
        help = "Adds an encryption-capable subkey [default: universal]",
        long_help =
            "Adds an encryption-capable subkey. \
            Encryption-capable subkeys can be marked as \
            suitable for transport encryption, storage \
            encryption, or both. \
            [default: universal]",
        arg_enum,
    )]
    pub can_encrypt: Option<KeyEncryptPurpose>,
    #[clap(
        long = "cannot-encrypt",
        help = "Adds no encryption-capable subkey",
    )]
    pub cannot_encrypt: bool,
    #[clap(
        short = 'e',
        long = "export",
        value_name = "OUTFILE",
        help = "Writes the key to OUTFILE",
    )]
    // TODO this represents a filename, so it should be a Path
    pub export: Option<String>,
    #[clap(
        long = "rev-cert",
        value_name = "FILE or -",
        required_if_eq("export", "-"),
        help = "Writes the revocation certificate to FILE",
        long_help =
            "Writes the revocation certificate to FILE. \
            mandatory if OUTFILE is \"-\". \
            [default: <OUTFILE>.rev]",
    )]
    // TODO this represents a filename, so it should be a Path
    pub rev_cert: Option<String>
}

#[derive(ArgEnum, Clone, Debug)]
pub enum KeyCipherSuite {
    Rsa3k,
    Rsa4k,
    Cv25519
}

#[derive(ArgEnum, Clone, Debug)]
pub enum KeyEncryptPurpose {
    Transport,
    Storage,
    Universal
}

#[derive(Debug, Args)]
#[clap(
    name = "password",
    display_order = 105,
    about = "Changes password protecting secrets",
    long_about = 
"Changes password protecting secrets

Secret key material in keys can be protected by a password.  This
subcommand changes or clears this encryption password.

To emit the key with unencrypted secrets, either use `--clear` or
supply a zero-length password when prompted for the new password.
",
    after_help =
"EXAMPLES:

# First, generate a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, encrypt the secrets in the key with a password.
$ sq key password < juliet.key.pgp > juliet.encrypted_key.pgp

# And remove the password again.
$ sq key password --clear < juliet.encrypted_key.pgp > juliet.decrypted_key.pgp
",
)]
pub struct KeyPasswordCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        long = "clear",
        help = "Emit a key with unencrypted secrets",
    )]
    pub clear: bool,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    name = "extract-cert",
    display_order = 110,
    about = "Converts a key to a cert",
    long_about =
"Converts a key to a cert

After generating a key, use this command to get the certificate
corresponding to the key.  The key must be kept secure, while the
certificate should be handed out to correspondents, e.g. by uploading
it to a keyserver.
",
    after_help = "EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this extracts the certificate for distribution
$ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp
",
)]
pub struct KeyExtractCertCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    name = "adopt",
    display_order = 800,
    about = "Binds keys from one certificate to another",
    long_about =
"Binds keys from one certificate to another

This command allows one to transfer primary keys and subkeys into an
existing certificate.  Say you want to transition to a new
certificate, but have an authentication subkey on your current
certificate.  You want to keep the authentication subkey because it
allows access to SSH servers and updating their configuration is not
feasible.
",
    after_help =
"EXAMPLES:

# Adopt an subkey into the new cert
$ sq key adopt --keyring juliet-old.pgp --key 0123456789ABCDEF -- juliet-new.pgp
",
)]
pub struct KeyAdoptCommand {
    #[clap(
        short = 'r',
        long = "keyring",
        value_name = "KEY-RING",
        help = "Supplies keys for use in --key.",
    )]
    pub keyring: Vec<String>,
    #[clap(
        short = 'k',
        long = "key",
        value_name = "KEY",
        required(true),
        help = "Adds the key or subkey KEY to the TARGET-KEY",
    )]
    // TODO Type should be KeyHandle, improve help
    pub key: Vec<String>,
    #[clap(
        long = "allow-broken-crypto",
        help = "Allows adopting keys from certificates \
            using broken cryptography",
    )]
    pub allow_broken_crypto: bool,
    #[clap(
        value_name = "TARGET-KEY",
        help = "Adds keys to TARGET-KEY",
    )]
    pub certificate: Option<String>,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}

#[derive(Debug, Args)]
#[clap(
    name = "attest-certifications",
    display_order = 200,
    about = "Attests to third-party certifications",
    long_about =
"
Attests to third-party certifications allowing for their distribution

To prevent certificate flooding attacks, modern key servers prevent
uncontrolled distribution of third-party certifications on
certificates.  To make the key holder the sovereign over the
information over what information is distributed with the certificate,
the key holder needs to explicitly attest to third-party
certifications.

After the attestation has been created, the certificate has to be
distributed, e.g. by uploading it to a keyserver.
",
    after_help =
"EXAMPLES:

# Attest to all certifications present on the key
$ sq key attest-certifications juliet.pgp

# Retract prior attestations on the key
$ sq key attest-certifications --none juliet.pgp
",
)]
pub struct KeyAttestCertificationsCommand {
    #[clap(
        long = "none",
        conflicts_with = "all",
        help = "Removes all prior attestations",
    )]
    pub none: bool,
    #[clap(
        long = "all",
        conflicts_with = "none",
        help = "Attests to all certifications [default]",
    )]
    pub all: bool,
    #[clap(
        value_name = "KEY",
        help = "Changes attestations on KEY",
    )]
    pub key: Option<String>,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,

}

#[derive(Parser, Debug)]
#[clap(
    name = "wkd",
    display_order = 420,
    about = "Interacts with Web Key Directories",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct WkdCommand {
    #[clap(
        short = 'p',
        long = "policy",
        value_name = "NETWORK-POLICY",
        default_value_t = NetworkPolicy::Encrypted,
        arg_enum,
        help = "Sets the network policy to use",
    )]
    pub policy: NetworkPolicy,
    #[clap(subcommand)]
    pub subcommand: WkdSubcommands,
}

#[derive(Debug, Subcommand)]
pub enum WkdSubcommands {
    Url(WkdUrlCommand),
    DirectUrl(WkdDirectUrlCommand),
    Get(WkdGetCommand),
    Generate(WkdGenerateCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Prints the advanced Web Key Directory URL of an email address.",
)]
pub struct WkdUrlCommand {
    #[clap(
        value_name = "ADDRESS",
        help = "Queries for ADDRESS",
    )]
    pub input: String,
}

#[derive(Debug, Args)]
#[clap(
    about = "Prints the direct Web Key Directory URL of an email address.",
)]
pub struct WkdDirectUrlCommand {
    #[clap(
        value_name = "ADDRESS",
        help = "Queries for ADDRESS",
    )]
    pub input: String,
}

#[derive(Debug, Args)]
#[clap(
    about = "Queries for certs using Web Key Directory",
)]
pub struct WkdGetCommand {
    #[clap(
        value_name = "ADDRESS",
        help = "Queries a cert for ADDRESS",
    )]
    pub input: String,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
}

#[derive(Debug, Args)]
#[clap(
    about = "Generates a Web Key Directory for the given domain and keys.",
    long_about = "Generates a Web Key Directory for the given domain and keys.  \
        If the WKD exists, the new keys will be inserted and it \
        is updated and existing ones will be updated. \
        \n
        \n
        A WKD is per domain, and can be queried using the advanced or the \
        direct method. The advanced method uses a URL with a subdomain \
        'openpgpkey'. As per the specification, the advanced method is to be \
        preferred. The direct method may only be used if the subdomain \
        doesn't exist. The advanced method allows web key directories for \
        several domains on one web server. \
        \n
        \n
        The contents of the generated WKD must be copied to a web server so that \
        they are accessible under https://openpgpkey.example.com/.well-known/openpgp/... \
        for the advanced version, and https://example.com/.well-known/openpgp/... \
        for the direct version. sq does not copy files to the web server.",
    after_help =
"EXAMPLES:

# Generate a WKD in /tmp/wkdroot from certs.pgp for example.com.
$ sq wkd generate /tmp/wkdroot example.com certs.ppg
",
)]
pub struct WkdGenerateCommand {
    #[clap(
        value_name = "WEB-ROOT",
        help = "Writes the WKD to WEB-ROOT",
        long_help = "Writes the WKD to WEB-ROOT. Transfer this directory to \
            the webserver.",
    )]
    pub base_directory: String,
    #[clap(
        value_name = "FQDN",
        help = "Generates a WKD for a fully qualified domain name for email",
    )]
    pub domain: String,
    #[clap(
        value_name = "CERT-RING",
        help = "Adds certificates from CERT-RING to the WKD",
    )]
    pub input: Option<String>,
    #[clap(
        short = 'd',
        long = "direct-method",
        help = "Uses the direct method [default: advanced method]",
    )]
    pub direct_method: bool,
    #[clap(
        short = 's',
        long = "skip",
        help = "Skips certificates that do not have User IDs for given domain.",
    )]
    pub skip: bool,
}

#[derive(Parser, Debug)]
#[clap(
    name = "keyserver",
    display_order = 410,
    about = "Interacts with keyservers",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct KeyserverCommand {
    #[clap(
        short,
        long,
        value_name = "NETWORK-POLICY",
        default_value_t = NetworkPolicy::Encrypted,
        help = "Sets the network policy to use",
        arg_enum,
    )]
    pub policy: NetworkPolicy,
    #[clap(
        short,
        long,
        value_name = "URI",
        help = "Sets the keyserver to use",
    )]
    pub server: Option<String>,
    #[clap(subcommand)]
    pub subcommand: KeyserverSubcommands,
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

#[derive(Debug, Subcommand)]
pub enum KeyserverSubcommands {
    Get(KeyserverGetCommand),
    Send(KeyserverSendCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Retrieves a key",
)]
pub struct KeyserverGetCommand {
    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        value_name = "QUERY",
        help = "Retrieve certificate(s) using QUERY. \
            This may be a fingerprint, a KeyID, \
            or an email address.",
    )]
    pub query: String,
}

#[derive(Debug, Args)]
#[clap(
    about = "Sends a key",
)]
pub struct KeyserverSendCommand {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Option<String>,
}

#[derive(Parser, Debug)]
#[clap(
    name = "inspect",
    display_order(600),
    about = "Inspects data, like file(1)",
    long_about =
"Inspects data, like file(1)

It is often difficult to tell from cursory inspection using cat(1) or
file(1) what kind of OpenPGP one is looking at.  This subcommand
inspects the data and provides a meaningful human-readable description
of it.
",
    after_help =
"EXAMPLES:

# Inspects a certificate
$ sq inspect juliet.pgp

# Inspects a certificate ring
$ sq inspect certs.pgp

# Inspects a message
$ sq inspect message.pgp

# Inspects a detached signature
$ sq inspect message.sig
",
)]
pub struct InspectCommand {
    #[clap(
        value_name = "FILE",
        help = "Reads from FILE or stdin if omitted",
    )]
    pub input: Option<String>,
    #[clap(
        long = "certifications",
        help = "Prints third-party certifications",
    )]
    pub certifications: bool,

}

#[derive(Parser, Debug)]
#[clap(
    name = "encrypt",
    display_order = 100,
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
$ sq encrypt --recipient-cert romeo.pgp message.txt

# Encrypt a file creating a signature in the process
$ sq encrypt --recipient-cert romeo.pgp --signer-key juliet.pgp message.txt

# Encrypt a file using a password
$ sq encrypt --symmetric message.txt
",
)]
pub struct EncryptCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
    #[clap(
        long = "recipient-cert",
        value_name = "CERT-RING",
        multiple_occurrences = true,
        help = "Encrypts for all recipients in CERT-RING",
    )]
    pub recipients_cert_file: Vec<String>,
    #[clap(
        long = "signer-key",
        value_name = "KEY",
        help = "Signs the message with KEY",
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
        default_value_t = EncryptEncryptionMode::All,
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
    pub mode: EncryptEncryptionMode,
    #[clap(
        long = "compression",
        value_name = "KIND",
        default_value_t = EncryptCompressionMode::Pad,
        help = "Selects compression scheme to use",
        arg_enum,
    )]
    pub compression: EncryptCompressionMode,
    #[clap(
        short = 't',
        long = "time",
        value_name = "TIME",
        help = "Chooses keys valid at the specified time and \
            sets the signature's creation time",
    )]
    pub time: Option<String>,
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
pub enum EncryptEncryptionMode {
    Transport,
    Rest,
    All
}

#[derive(ArgEnum, Debug, Clone)]
pub enum EncryptCompressionMode {
    None,
    Pad,
    Zip,
    Zlib,
    Bzip2
}


#[derive(Parser, Debug)]
#[clap(
    name = "decrypt",
    display_order = 110,
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
pub struct CliSessionKey {
    pub session_key: SessionKey,
    pub symmetric_algo: Option<SymmetricAlgorithm>,
}

impl std::str::FromStr for CliSessionKey {
    type Err = anyhow::Error;

    /// Parse a session key. The format is: an optional prefix specifying the
    /// symmetric algorithm as a number, followed by a colon, followed by the
    /// session key in hexadecimal representation.
    fn from_str(sk: &str) -> anyhow::Result<Self> {
        let result = if let Some((algo, sk)) = sk.split_once(':') {
            let algo = SymmetricAlgorithm::from(algo.parse::<u8>()?);
            let dsk = hex::decode_pretty(sk)?.into();
            CliSessionKey {
                session_key: dsk,
                symmetric_algo: Some(algo),
            }
        } else {
            let dsk = hex::decode_pretty(sk)?.into();
            CliSessionKey {
                session_key: dsk,
                symmetric_algo: None,
            }
        };
        Ok(result)
    }
}

impl CliSessionKey {

    /// Returns an object that implements Display for explicitly opting into
    /// printing a `SessionKey`.
    pub fn display_sensitive(&self) -> CliSessionKeyDisplay {
        CliSessionKeyDisplay { csk: self }
    }
}

/// Helper struct for intentionally printing session keys with format! and {}.
///
/// This struct implements the `Display` trait to print the session key. This
/// construct requires the user to explicitly call
/// [`CliSessionKey::display_sensitive`]. By requiring the user to opt-in, this
/// will hopefully reduce that the chance that the session key is inadvertently
/// leaked, e.g., in a log that may be publicly posted.
pub struct CliSessionKeyDisplay<'a> {
    csk: &'a CliSessionKey,
}

/// Print the session key without prefix in hexadecimal representation.
impl<'a> std::fmt::Display for CliSessionKeyDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let sk = self.csk;
        write!(f, "{}", hex::encode(&sk.session_key))
    }
}

#[cfg(feature = "autocrypt")]
pub mod autocrypt {
    use super::*;

    #[derive(Parser, Debug)]
    #[clap(
        name = "autocrypt",
        display_order(400),
        about = "Communicates certificates using Autocrypt",
        long_about =
"Communicates certificates using Autocrypt

Autocrypt is a standard for mail user agents to provide convenient
end-to-end encryption of emails.  This subcommand provides a limited
way to produce and consume headers that are used by Autocrypt to
communicate certificates between clients.

See https://autocrypt.org/
",
        subcommand_required = true,
        arg_required_else_help = true,
    )]
    pub struct AutocryptCommand {
        #[clap(subcommand)]
        pub subcommand: AutocryptSubcommands,
    }

    #[derive(Debug, Subcommand)]
    pub enum AutocryptSubcommands {
        Decode(AutocryptDecodeCommand),

        EncodeSender(AutocryptEncodeSenderCommand),
    }

    #[derive(Debug, Args)]
    #[clap(
        about = "Reads Autocrypt-encoded certificates",
        long_about =
"Reads Autocrypt-encoded certificates

Given an autocrypt header (or an key-gossip header), this command
extracts the certificate encoded within it.

The converse operation is \"sq autocrypt encode-sender\".
",
        after_help =
"EXAMPLES:

# Extract all certificates from a mail
$ sq autocrypt decode autocrypt.eml
",
    )]
    pub struct AutocryptDecodeCommand {
        #[clap(flatten)]
        pub io: IoArgs,
        #[clap(
            short = 'B',
            long,
            help = "Emits binary data",
        )]
        pub binary: bool,
    }

    //#[derive(Subcommand)]
    #[derive(Debug, Args)]
    #[clap(
        name = "encode-sender",
        about = "Encodes a certificate into an Autocrypt header",
        long_about =
"Encodes a certificate into an Autocrypt header

A certificate can be encoded and included in a header of an email
message.  This command encodes the certificate, adds the senders email
address (which must match the one used in the \"From\" header), and the
senders \"prefer-encrypt\" state (see the Autocrypt spec for more
information).

The converse operation is \"sq autocrypt decode\".
",
        after_help =
"EXAMPLES:

# Encodes a certificate
$ sq autocrypt encode-sender juliet.pgp

# Encodes a certificate with an explicit sender address
$ sq autocrypt encode-sender --email juliet@example.org juliet.pgp

# Encodes a certificate while indicating the willingness to encrypt
$ sq autocrypt encode-sender --prefer-encrypt mutual juliet.pgp
",
    )]
    pub struct AutocryptEncodeSenderCommand {
        #[clap(flatten)]
        pub io: IoArgs,
        // TODO the help message looks like "primary userid" might be the default
        // email. clarify
        #[clap(
            long = "email",
            value_name = "ADDRESS",
            help = "Sets the address [default: primary userid]",
        )]
        pub address: Option<String>,
        #[clap(
            long = "prefer-encrypt",
            value_name = "PREFER-ENCRYPT",
            default_value_t = PreferEncryptArgs::NoPreference,
            help = "Sets the prefer-encrypt attribute",
            arg_enum,
        )]
        pub prefer_encrypt: PreferEncryptArgs,

    }

    #[derive(ArgEnum, Debug, Clone)]
    pub enum PreferEncryptArgs {
        #[clap(name = "nopreference")]
        NoPreference,
        Mutual
    }

    impl std::fmt::Display for PreferEncryptArgs {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                PreferEncryptArgs::Mutual => write!(f, "mutual"),
                PreferEncryptArgs::NoPreference => write!(f, "nopreference"),
            }
        }
    }
}
