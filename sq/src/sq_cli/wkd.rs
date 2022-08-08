use clap::{Args, Parser, Subcommand};

use super::NetworkPolicy;

#[derive(Parser, Debug)]
#[clap(
    name = "wkd",
    about = "Interacts with Web Key Directories",
    subcommand_required = true,
    arg_required_else_help = true,
    setting(clap::AppSettings::DeriveDisplayOrder),
)]
pub struct WkdCommand {
    #[clap(
        short,
        long,
        value_name = "NETWORK-POLICY",
        default_value_t = NetworkPolicy::Encrypted,
        arg_enum,
        help = "Sets the network policy to use",
    )]
    pub network_policy: NetworkPolicy,
    #[clap(subcommand)]
    pub subcommand: WkdSubcommands,
}

#[derive(Debug, Subcommand)]
pub enum WkdSubcommands {
    Generate(WkdGenerateCommand),
    Get(WkdGetCommand),
    DirectUrl(WkdDirectUrlCommand),
    Url(WkdUrlCommand),
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
    pub email_address: String,
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
    pub email_address: String,
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
    pub email_address: String,
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
    long_about =
"Generates a Web Key Directory for the given domain and keys

If the WKD exists, the new keys will be inserted and it \
is updated and existing ones will be updated.

A WKD is per domain, and can be queried using the advanced or the \
direct method. The advanced method uses a URL with a subdomain \
'openpgpkey'. As per the specification, the advanced method is to be \
preferred. The direct method may only be used if the subdomain \
doesn't exist. The advanced method allows web key directories for \
several domains on one web server.

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
