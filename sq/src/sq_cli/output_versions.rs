use clap::Parser;

#[derive(Parser, Debug)]
#[clap(
    name = "output-versions",
    display_order = 110,
    about = "List supported output versions",
)]
pub struct Command {
    /// List only the default output version.
    #[clap(long)]
    pub default: bool,
}
