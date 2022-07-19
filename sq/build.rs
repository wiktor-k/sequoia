use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use clap_complete::Shell;
use anyhow::Result;

pub mod sq_cli {
    include!("src/sq_cli.rs");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Generate subplot tests.
    subplot_build::codegen(Path::new("sq-subplot.md"))
        .expect("failed to generate code with Subplot");

    let mut sq = sq_cli::build();

    // Dump help output of all commands and subcommands, for inclusion in docs
    dump_help(sq.clone()).unwrap();

    // Generate shell completions
    let outdir = match env::var_os("CARGO_TARGET_DIR") {
        None => return,
        Some(outdir) => outdir,
    };

    fs::create_dir_all(&outdir).unwrap();

    for shell in &[Shell::Bash, Shell::Fish, Shell::Zsh, Shell::PowerShell,
                   Shell::Elvish] {
        let path = clap_complete::generate_to(*shell, &mut sq, "sq", &outdir).unwrap();
        println!("cargo:warning=completion file is generated: {:?}", path);
    };
}

fn dump_help(mut cmd: clap::Command) -> Result<()> {
    cmd = cmd.term_width(80);
    cmd.build();
    let mut sink = fs::File::create("sq-usage.md")?;

    writeln!(sink, "A command-line frontend for Sequoia.")?;
    writeln!(sink)?;
    writeln!(sink, "# Usage")?;
    dump_help_inner(&mut sink, &mut cmd, "##")
}

fn dump_help_inner(
    sink: &mut dyn Write,
    cmd: &mut clap::Command,
    heading: &str,
) -> Result<()> {
    writeln!(sink)?;

    let mut buffer = Vec::new();
    let _ = cmd.write_long_help(&mut buffer);
    let help = std::str::from_utf8(buffer.as_slice())?;

    writeln!(sink, "```text")?;
    for line in help.trim_end().split('\n').skip(1) {
        if line.is_empty() {
            writeln!(sink)?;
        } else {
            writeln!(sink, "{}", line.trim_end())?;
        }
    }
    writeln!(sink, "```")?;

    // Recurse.
    for subcommand in cmd
        .get_subcommands_mut()
        .filter(|sc| sc.get_name() != "help")
    {
        writeln!(sink)?;
        let heading_name = subcommand
            // cmd.build() in dump_help makes sure every subcommand has a display_name
            .get_display_name()
            .unwrap()
            .replace('-', " ");
        writeln!(sink, "{} Subcommand {}", heading, heading_name)?;

        dump_help_inner(sink, subcommand, &format!("{}#", heading))?;
    }

    Ok(())
}
