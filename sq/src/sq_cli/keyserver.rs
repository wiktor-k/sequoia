use clap::{Args, Parser, Subcommand};

use crate::sq_cli::types::NetworkPolicy;

#[derive(Parser, Debug)]
#[clap(
    name = "keyserver",
    about = "Interacts with keyservers",
    subcommand_required = true,
    arg_required_else_help = true,
)]
pub struct Command {
    #[clap(
        short = 'p',
        long = "policy",
        value_name = "NETWORK-POLICY",
        default_value_t = NetworkPolicy::Encrypted,
        help = "Sets the network policy to use",
        arg_enum,
    )]
    pub network_policy: NetworkPolicy,
    #[clap(
        short,
        long,
        value_name = "URI",
        help = "Sets the keyserver to use",
    )]
    pub server: Option<String>,
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Get(GetCommand),
    Send(SendCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Retrieves a key",
)]
pub struct GetCommand {
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
pub struct SendCommand {
    #[clap(value_name = "FILE", help = "Reads from FILE or stdin if omitted")]
    pub input: Option<String>,
}
