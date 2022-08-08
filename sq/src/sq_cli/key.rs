use clap::{ArgEnum, ArgGroup, Args, Parser, Subcommand};

use super::{IoArgs, CliTime};

#[derive(Parser, Debug)]
#[clap(
    name = "key",
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
    setting(clap::AppSettings::DeriveDisplayOrder),
)]
pub struct KeyCommand {
    #[clap(subcommand)]
    pub subcommand: KeySubcommands,
}

#[derive(Debug, Subcommand)]
pub enum KeySubcommands {
    Generate(KeyGenerateCommand),
    Password(KeyPasswordCommand),
    #[clap(subcommand)]
    Userid(KeyUseridCommand),
    ExtractCert(KeyExtractCertCommand),
    AttestCertifications(KeyAttestCertificationsCommand),
    Adopt(KeyAdoptCommand),
}

#[derive(Debug, Args)]
#[clap(
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
Sets the key's creation time to TIME.  TIME is interpreted as an ISO 8601 \
timestamp.  To set the creation time to June 9, 2011 at midnight UTC, \
you can do:

$ sq key generate --creation-time 20110609 --export noam.pgp

To include a time, add a T, the time and optionally the timezone (the \
default timezone is UTC):

$ sq key generate --creation-time 20110609T1938+0200 --export noam.pgp
",
    )]
    pub creation_time: Option<CliTime>,
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

#[derive(Debug, Subcommand)]
#[clap(
    name = "userid",
    about = "Manages User IDs",
    long_about =
"Manages User IDs

Add User IDs to, or strip User IDs from a key.
",
    subcommand_required = true,
    arg_required_else_help = true,
    setting(clap::AppSettings::DeriveDisplayOrder),
)]
pub enum KeyUseridCommand {
    Add(KeyUseridAddCommand),
    Strip(KeyUseridStripCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Adds a User ID",
    long_about =
"Adds a User ID

A User ID can contain a name, like \"Juliet\" or an email address, like
\"<juliet@example.org>\".  Historically, a name and email address were often
combined as a single User ID, like \"Juliet <juliet@example.org>\".
",
    after_help =
"EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this adds a User ID
$ sq key userid add --userid \"Juliet\" juliet.key.pgp \\
  --output juliet-new.key.pgp
",
)]
pub struct KeyUseridAddCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        value_name = "USERID",
        short,
        long,
        help = "User ID to add",
    )]
    pub userid: Vec<String>,
    #[clap(
        long = "creation-time",
        value_name = "CREATION_TIME",
        help = "Sets the binding signature creation time to TIME (as ISO 8601)",
        long_help = "\
Sets the creation time of this User ID's binding signature to TIME. \
TIME is interpreted as an ISO 8601 timestamp.  To set the creation \
time to June 28, 2022 at midnight UTC, you can do:

$ sq key userid add --userid \"Juliet\" --creation-time 20210628 \\
   juliet.key.pgp --output juliet-new.key.pgp

To include a time, add a T, the time and optionally the timezone (the \
default timezone is UTC):

$ sq key userid add --userid \"Juliet\" --creation-time 20210628T1137+0200 \\
   juliet.key.pgp --output juliet-new.key.pgp
",
    )]
    pub creation_time: Option<CliTime>,
    #[clap(
        long = "private-key-store",
        value_name = "KEY_STORE",
        help = "Provides parameters for private key store",
    )]
    pub private_key_store: Option<String>,
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,
}


#[derive(Debug, Args)]
#[clap(
    about = "Strips a User ID",
    long_about =
"Strips a User ID

Note that this operation does not reliably remove User IDs from a
certificate that has already been disseminated! (OpenPGP software
typically appends new information it receives about a certificate
to its local copy of that certificate.  Systems that have obtained
a copy of your certificate with the User ID that you are trying to
strip will not drop that User ID from their copy.)

In most cases, you will want to use the 'sq revoke userid' operation
instead.  That issues a revocation for a User ID, which can be used to mark
the User ID as invalidated.

However, this operation can be useful in very specific cases, in particular:
to remove a mistakenly added User ID before it has been uploaded to key
servers or otherwise shared.

Stripping a User ID may change how a certificate is interpreted.  This
is because information about the certificate like algorithm preferences,
the primary key's key flags, etc. is stored in the User ID's binding
signature.
",
    after_help =
"EXAMPLES:

# First, this generates a key
$ sq key generate --userid \"<juliet@example.org>\" --export juliet.key.pgp

# Then, this strips a User ID
$ sq key userid strip --userid \"<juliet@example.org>\" \\
  --output juliet-new.key.pgp juliet.key.pgp
",
)]
pub struct KeyUseridStripCommand {
    #[clap(flatten)]
    pub io: IoArgs,
    #[clap(
        value_name = "USERID",
        short,
        long,
        help = "User IDs to strip",
        long_help = "The User IDs to strip.  Values must exactly match a \
User ID."
    )]
    pub userid: Vec<String>,
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
    about = "Attests to third-party certifications",
    long_about =
"Attests to third-party certifications allowing for their distribution

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
