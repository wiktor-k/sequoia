use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
#[clap(
    name = "certify",
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
pub struct Command {
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
Sets the certification time to TIME.  TIME is interpreted as an ISO 8601 \
timestamp.  To set the certification time to June 9, 2011 at midnight UTC, \
you can do:

$ sq certify --time 20130721 neal.pgp ada.pgp ada

To include a time, add a T, the time and optionally the timezone (the \
default timezone is UTC):

$ sq certify --time 20130721T0550+0200 neal.pgp ada.pgp ada
",
    )]
    pub time: Option<String>,
    #[clap(
        short = 'd',
        long = "depth",
        value_name = "TRUST_DEPTH",
        default_value = "0",
        help = "Sets the trust depth",
        long_help =
            "Sets the trust depth (sometimes referred to as the trust level).  \
            0 means a normal certification of <CERTIFICATE, USERID>.  \
            1 means CERTIFICATE is also a trusted introducer, 2 means \
            CERTIFICATE is a meta-trusted introducer, etc.",
    )]
    pub depth: u8,
    #[clap(
        short = 'a',
        long = "amount",
        value_name = "TRUST_AMOUNT",
        default_value = "120",
        help = "Sets the amount of trust",
        long_help =
            "Sets the amount of trust.  Values between 1 and 120 are meaningful. \
            120 means fully trusted.  Values less than 120 indicate the degree \
            of trust.  60 is usually used for partially trusted.",
    )]
    //TODO: use usize, not String
    pub amount: u8,
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
