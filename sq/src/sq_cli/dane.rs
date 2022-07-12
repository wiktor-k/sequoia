use clap::{Args, Parser, Subcommand};

use crate::sq_cli::types::NetworkPolicy;

#[derive(Parser, Debug)]
#[clap(
    name = "dane",
    about = "Interacts with DANE",
    long_about = "DNS-Based Authentication of Named Entities (DANE) is a method for publishing public keys in DNS as specified in RFC 7929.",
    subcommand_required = true,
    arg_required_else_help = true,
    setting(clap::AppSettings::DeriveDisplayOrder),
)]
pub struct Command {
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
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Get(GetCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Queries for certs using DANE",
)]
pub struct GetCommand {
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
