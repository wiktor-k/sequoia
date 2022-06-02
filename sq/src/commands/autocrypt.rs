use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Result,
    armor,
    parse::Parse,
    serialize::Serialize,
};
use sequoia_autocrypt as autocrypt;

use crate::{
    Config,
    open_or_stdin,
    sq_cli,
};

use sq_cli::autocrypt::{AutocryptSubcommands, AutocryptCommand};

pub fn dispatch(config: Config, c: &AutocryptCommand) -> Result<()> {

    match &c.subcommand {
        AutocryptSubcommands::Decode(command) => {
            let input = open_or_stdin(command.io.input.as_deref())?;
            let mut output = config.create_or_stdout_pgp(
                command.io.output.as_deref(),
                command.binary,
                armor::Kind::PublicKey,
            )?;
            let ac = autocrypt::AutocryptHeaders::from_reader(input)?;
            for h in &ac.headers {
                if let Some(ref cert) = h.key {
                    cert.serialize(&mut output)?;
                }
            }
            output.finalize()?;
        }
        AutocryptSubcommands::EncodeSender(command) => {
            let input = open_or_stdin(command.io.input.as_deref())?;
            let mut output =
                config.create_or_stdout_safe(command.io.output.as_deref())?;
            let cert = Cert::from_reader(input)?;
            let addr = command.address.clone()
                .or_else(|| {
                    cert.with_policy(&config.policy, None)
                        .and_then(|vcert| vcert.primary_userid()).ok()
                        .map(|ca| ca.userid().to_string())
                });
            let ac = autocrypt::AutocryptHeader::new_sender(
                &config.policy,
                &cert,
                &addr.ok_or_else(|| anyhow::anyhow!(
                    "No well-formed primary userid found, use \
                     --address to specify one"))?,
                Some(command.prefer_encrypt.to_string().as_str()))?;
            write!(&mut output, "Autocrypt: ")?;
            ac.serialize(&mut output)?;
        },
    }

    Ok(())
}

