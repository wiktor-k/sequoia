//! DANE protocol client.
//!
//! [DANE] is a protocol for retrieving and storing OpenPGP
//! certificates in the DNS.
//!
//! [DANE]: https://datatracker.ietf.org/doc/html/rfc7929

use super::email::EmailAddress;

use sequoia_openpgp::{
    fmt,
    Cert,
    parse::Parse,
    types::HashAlgorithm,
    cert::prelude::*,
};

use super::Result;

use trust_dns_client::rr::{RData, RecordType};
use trust_dns_resolver::config::ResolverOpts;
use trust_dns_resolver::TokioAsyncResolver;

/// Generates a Fully Qualified Domain Name that holds the OPENPGPKEY
/// record for given `local` and `domain` parameters.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7929>
fn generate_fqdn(local: &str, domain: &str) -> Result<String> {
    let mut ctx = HashAlgorithm::SHA256.context()?;
    ctx.update(local.as_bytes());

    let mut digest = vec![0; ctx.digest_size()];
    ctx.digest(&mut digest)?;

    Ok(format!(
        "{}._openpgpkey.{}",
        fmt::hex::encode(&digest[..28]),
        domain
    ))
}

/// Retrieves raw values for `OPENPGPKEY` records for User IDs with a
/// given e-mail address using the [DANE] protocol.
///
/// This function unconditionally validates DNSSEC records and returns
/// the found certificates only on validation success.
///
/// [DANE]: https://datatracker.ietf.org/doc/html/rfc7929
///
/// # Examples
///
/// ```no_run
/// # use sequoia_net::{Result, dane};
/// # use sequoia_openpgp::Cert;
/// # async fn f() -> Result<()> {
/// let email_address = "john@example.com";
/// let certs = dane::get_raw(email_address).await?;
/// # Ok(())
/// # }
/// ```
pub async fn get_raw(email_address: impl AsRef<str>) -> Result<Vec<Vec<u8>>> {
    let email_address = EmailAddress::from(email_address)?;
    let fqdn = generate_fqdn(&email_address.local_part, &email_address.domain)?;

    let mut opts = ResolverOpts::default();
    opts.validate = true;

    let resolver = TokioAsyncResolver::tokio(Default::default(), opts)?;

    let answers = resolver
        .lookup(fqdn, RecordType::OPENPGPKEY)
        .await?;

    let mut bytes = vec![];

    for record in answers.iter() {
        if let RData::OPENPGPKEY(key) = record {
            bytes.push(key.public_key().into());
        }
    }

    Ok(bytes)
}

/// Retrieves certificates that contain User IDs with a given e-mail
/// address using the [DANE] protocol.
///
/// This function unconditionally validates DNSSEC records and returns
/// the found certificates only on validation success.
///
/// [DANE]: https://datatracker.ietf.org/doc/html/rfc7929
///
/// # Examples
///
/// ```no_run
/// # use sequoia_net::{Result, dane};
/// # use sequoia_openpgp::Cert;
/// # async fn f() -> Result<()> {
/// let email_address = "john@example.com";
/// let certs = dane::get(email_address).await?;
/// # Ok(())
/// # }
/// ```
pub async fn get(email_address: impl AsRef<str>) -> Result<Vec<Cert>> {
    let mut certs = vec![];

    for bytes in get_raw(email_address).await?.iter() {
        certs.extend(CertParser::from_bytes(bytes)?.flatten());
    }

    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generating_fqdn() {
        assert_eq!(
            generate_fqdn("dkg", "debian.org").unwrap(),
            "A47CB586A51ACB93ACB9EF806F35F29131548E59E2FACD58CF6232E3._openpgpkey.debian.org"
        );
    }

    #[test]
    fn test_generating_fqdn_lower_case() {
        // Must NOT lowercase "DKG" into "dkg".
        // See: https://datatracker.ietf.org/doc/html/rfc7929#section-4
        assert_eq!(
            generate_fqdn("DKG", "DEBIAN.ORG").unwrap(),
            "46DE800073B375157AD8F4371E2713E118E3128FB1B4321ACE452F95._openpgpkey.DEBIAN.ORG"
        );
    }
}
