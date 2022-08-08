use clap::Parser;
use clap::{ArgEnum, Args, Subcommand};

use sequoia_openpgp as openpgp;

use super::CliTime;

#[derive(Parser, Debug)]
#[clap(
    name = "revoke",
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
    setting(clap::AppSettings::DeriveDisplayOrder),
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
    pub time: Option<CliTime>,
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

use openpgp::types::ReasonForRevocation as OpenPGPRevocationReason;
impl From<RevocationReason> for OpenPGPRevocationReason {
    fn from(rr: RevocationReason) -> Self {
        match rr {
            RevocationReason::Compromised => OpenPGPRevocationReason::KeyCompromised,
            RevocationReason::Superseded => OpenPGPRevocationReason::KeySuperseded,
            RevocationReason::Retired => OpenPGPRevocationReason::KeyRetired,
            RevocationReason::Unspecified => OpenPGPRevocationReason::Unspecified,
        }
    }
}

#[derive(Debug, Args)]
#[clap(
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
    pub time: Option<CliTime>,
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
    pub time: Option<CliTime>,
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

impl From<UseridRevocationReason> for OpenPGPRevocationReason {
    fn from(rr: UseridRevocationReason) -> Self {
        match rr {
            UseridRevocationReason::Retired => OpenPGPRevocationReason::UIDRetired,
            UseridRevocationReason::Unspecified => OpenPGPRevocationReason::Unspecified,
        }
    }
}
