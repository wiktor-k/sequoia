//! Data types for output format and format version choice.
//!
//! These data types express the values of the `--output-format` and
//! `--output-version` global options to `sq`.

use std::fmt;
use std::str::FromStr;
use std::io::Write;

use anyhow::{anyhow, Result};
use serde::Serialize;

pub use keyring::ListItem as KeyringListItem;
pub use wkd::WkdUrlVariant;

/// What output format to prefer, when there's an option?
#[derive(Clone)]
pub enum OutputFormat {
    /// Output that is meant to be read by humans, instead of programs.
    ///
    /// This type of output has no version, and is not meant to be
    /// parsed by programs.
    HumanReadable,

    /// Output as JSON.
    Json,
}

impl FromStr for OutputFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "human-readable" => Ok(Self::HumanReadable),
            "json" => Ok(Self::Json),
            _ => Err(anyhow!("unknown output format {:?}", s)),
        }
    }
}

/// What version of the output format is used or requested?
///
/// As `sq` evolves, the machine-readable output format may need to
/// change. Consumers should be able to know what version of the output
/// format has been produced. This is expressed using a three-part
/// version number, which is always included in the output, similar to
/// [Semantic Versions][]. The parts are known as "major", "minor",
/// and "patch", and have the following semantics:
///
/// * patch: incremented if there are no semantic changes
/// * minor: one or more fields were added
/// * major: one or more fields were dropped
///
/// [Semantic Version]: https://semver.org/
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct OutputVersion {
    major: usize,
    minor: usize,
    patch: usize,
}

impl OutputVersion {
    /// Create a new version number from constituent parts.
    pub const fn new(major: usize, minor: usize, patch: usize) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Does this version fulfill the needs of the version that is requested?
    pub fn is_acceptable_for(&self, wanted: Self) -> bool {
        self.major == wanted.major &&
            (self.minor > wanted.minor ||
             (self.minor == wanted.minor && self.patch >= wanted.patch))
    }
}

impl FromStr for OutputVersion {
    type Err = anyhow::Error;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        let ints = parse_ints(v)?;
        match ints.len() {
            0 => Err(anyhow!("doesn't look like a version: {}", v)),
            1 => Ok(Self::new(ints[0], 0, 0)),
            2 => Ok(Self::new(ints[0], ints[1], 0)),
            3 => Ok(Self::new(ints[0], ints[1], ints[2])),
            _ => Err(anyhow!("too many components in version (at most three allowed): {}", v)),
        }
    }
}

impl fmt::Display for OutputVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

fn parse_ints(s: &str) -> Result<Vec<usize>> {
    let mut ints = vec![];
    let mut v = s;
    while !v.is_empty() {
        if let Some(i) = v.find('.') {
            ints.push(parse_component(&v[..i])?);
            v = &v[i+1..];
            if v.is_empty() {
                return Err(anyhow!("trailing dot in version: {}", s));
            }
        } else {
            ints.push(parse_component(v)?);
            v = "";
        }
    }
    Ok(ints)
}

fn parse_component(s: &str) -> Result<usize> {
    Ok(FromStr::from_str(s)?)
}

/// A model for the output of `sq` subcommands.
///
/// This is for adding machine-readable output (such as JSON) to
/// subcommand. Every subcommand is represented as a variant, for each
/// version of the output. Versioning is global. We keep the latest
/// subversion of each major version.
///
/// Each variant is created by a dedicated function.
pub enum Model {
    KeyringListV0(keyring::ListV0),
    WkdUrlV0(wkd::UrlV0),
}

impl Model {
    const DEFAULT_VERSION: OutputVersion = OutputVersion::new(0, 0, 0);

    fn version(v: Option<OutputVersion>) -> OutputVersion {
        v.unwrap_or(Self::DEFAULT_VERSION)
    }

    /// Create a model for the output of `sq wkd url` and `sq wkd
    /// direct-url` subcommands.
    pub fn wkd_url(version: Option<OutputVersion>,
                   variant: wkd::WkdUrlVariant,
                   advanced_url: String,
                   direct_url: String) -> Result<Self> {
        let version = Self::version(version);
        let result = match version {
            wkd::UrlV0::V => Self::WkdUrlV0(wkd::UrlV0::new(variant, advanced_url, direct_url)),
            _ => return Err(anyhow!("unknown output version {:?}", version)),
        };
        Ok(result)
    }

    /// Create a model for the output of the `sq keyring list`
    /// subcommand.
    pub fn keyring_list(version: Option<OutputVersion>, certs: Vec<keyring::ListItem>, all_uids: bool) -> Result<Self> {
        let version = Self::version(version);
        let result = match version {
            keyring::ListV0::V => Self::KeyringListV0(keyring::ListV0::new(certs, all_uids)),
            _ => return Err(anyhow!("unknown output version {:?}", version)),
        };
        Ok(result)
    }

    /// Write the output of a model to an open write handle in the
    /// format requested by the user.
    pub fn write(&self, format: OutputFormat, w: &mut dyn Write) -> Result<()> {
        match self {
            Self::KeyringListV0(x) => {
                match format {
                    OutputFormat::HumanReadable => x.human_readable(w)?,
                    OutputFormat::Json => x.json(w)?
                }
            }
            Self::WkdUrlV0(x) => {
                match format {
                    OutputFormat::HumanReadable => x.human_readable(w)?,
                    OutputFormat::Json => x.json(w)?
                }
            }
        }
        Ok(())
    }
}

// Model output as a data type that can be serialized.
mod keyring {
    use sequoia_openpgp as openpgp;
    use openpgp::{
        Result,
        cert::Cert,
    };
    use crate::Config;
    use super::{OutputVersion, Write};
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    pub struct ListV0 {
        #[serde(skip)]
        all_uids: bool,
        sq_output_version: OutputVersion,
        keys: Vec<ListItem>,
    }

    impl ListV0 {
        pub const V: OutputVersion = OutputVersion::new(0, 0, 0);

        pub fn new(keys: Vec<ListItem>, all_uids: bool) -> Self {
            Self {
                all_uids,
                sq_output_version: Self::V,
                keys,
            }
        }

        pub fn human_readable(&self, w: &mut dyn Write) -> Result<()> {
            for (i, item) in self.keys.iter().enumerate() {
                match item {
                    ListItem::Error(e) => {
                        writeln!(w, "{}. {}", i, e)?;
                    },
                    ListItem::Cert(cert) => {
                        let line = format!("{}. {}", i, cert.fingerprint);
                        let indent = line.chars().map(|_| ' ').collect::<String>();
                        write!(w, "{}", line)?;
                        match &cert.primary_userid {
                            Some(uid) => writeln!(w, " {}", uid)?,
                            None => writeln!(w)?,
                        }
                        if self.all_uids {
                            for uid in &cert.userids {
                                writeln!(w, "{} {}", indent, uid)?;
                            }
                        }
                    }
                }
            }
            Ok(())
        }

        pub fn json(&self, w: &mut dyn Write) -> Result<()> {
            serde_json::to_writer_pretty(w, &self)?;
//            writeln!(w)?;
            Ok(())
        }
    }

    #[derive(Debug, Serialize)]
    #[serde(untagged)]
    pub enum ListItem {
        Error(String),
        Cert(OutputCert),
    }

    impl ListItem {
        pub fn write(&self, i: usize, list_all_userids: bool) {
            match self {
                ListItem::Error(e) => {
                    println!("{}. {}", i, e);
                },
                ListItem::Cert(cert) => {
                    let line = format!("{}. {}", i, cert.fingerprint);
                    let indent = line.chars().map(|_| ' ').collect::<String>();
                    print!("{}", line);
                    match &cert.primary_userid {
                        Some(uid) => println!(" {}", uid),
                        None => println!(),
                    }
                    if list_all_userids {
                        for uid in &cert.userids {
                            println!("{} {}", indent, uid);
                        }
                    }
                }
            }
        }

        pub fn from_cert_with_config(item: Result<Cert>, config: &Config) -> Self {
            match item {
                Ok(cert) => ListItem::Cert(OutputCert::from_cert_with_config(cert, config)),
                Err(e) => ListItem::Error(format!("{}", e)),
            }
        }
    }

    #[derive(Debug, Serialize)]
    pub struct OutputCert {
        fingerprint: String,
        primary_userid: Option<String>,
        userids: Vec<String>,
    }

    impl OutputCert {
        fn from_cert_with_config(cert: Cert, config: &Config) -> Self {
            // Try to be more helpful by including a User ID in the
            // listing.  We'd like it to be the primary one.  Use
            // decreasingly strict policies.
            let mut primary_uid: Option<Vec<u8>> = None;

            // First, apply our policy.
            if let Ok(vcert) = cert.with_policy(&config.policy, None) {
                if let Ok(primary) = vcert.primary_userid() {
                    primary_uid = Some(primary.value().to_vec());
                }
            }

            // Second, apply the null policy.
            if primary_uid.is_none() {
                let null = openpgp::policy::NullPolicy::new();
                if let Ok(vcert) = cert.with_policy(&null, None) {
                    if let Ok(primary) = vcert.primary_userid() {
                        primary_uid = Some(primary.value().to_vec());
                    }
                }
            }

            // As a last resort, pick the first user id.
            if primary_uid.is_none() {
                if let Some(primary) = cert.userids().next() {
                    primary_uid = Some(primary.value().to_vec());
                }
            }

            // List all user ids independently of their validity.
            let mut userids = vec![];
            for u in cert.userids() {
                if primary_uid.as_ref()
                    .map(|p| &p[..] == u.value()).unwrap_or(false)
                {
                    // Skip the user id we already handled.
                    continue;
                }

                userids.push(Self::userid(u.value()));
            }

            Self {
                fingerprint: format!("{:X}", cert.fingerprint()),
                primary_userid: primary_uid.map(|id| Self::userid(&id)),
                userids,
            }
        }

        fn userid(bytes: &[u8]) -> String {
            String::from_utf8_lossy(bytes).into()
        }
    }
}

// Model output as a data type that can be serialized.
pub mod wkd {
    use super::{OutputVersion, Result, Write};
    use serde::Serialize;

    #[derive(Debug)]
    pub enum WkdUrlVariant {
        Advanced,
        Direct,
    }

    #[derive(Debug, Serialize)]
    pub struct UrlV0 {
        #[serde(skip)]
        variant: WkdUrlVariant,
        sq_output_version: OutputVersion,
        advanced_url: String,
        direct_url: String,
    }

    impl UrlV0 {
        pub const V: OutputVersion = OutputVersion::new(0, 0, 0);

        pub fn new(variant: WkdUrlVariant, advanced_url: String, direct_url: String) -> Self {
            Self {
                sq_output_version: Self::V,
                variant,
                advanced_url,
                direct_url,
            }
        }

        pub fn human_readable(&self, w: &mut dyn Write) -> Result<()> {
            match self.variant {
                WkdUrlVariant::Advanced => writeln!(w, "{}", self.advanced_url)?,
                WkdUrlVariant::Direct => writeln!(w, "{}", self.direct_url)?,
            }
            Ok(())
        }

        pub fn json(&self, w: &mut dyn Write) -> Result<()> {
            serde_json::to_writer_pretty(w, self)?;
//            writeln!(w)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::{FromStr, OutputVersion};

    #[test]
    fn empty_string() {
        assert!(OutputVersion::from_str("").is_err());
    }

    #[test]
    fn not_int() {
        assert!(OutputVersion::from_str("foo").is_err());
    }

    #[test]
    fn not_int2() {
        assert!(OutputVersion::from_str("1.foo").is_err());
    }

    #[test]
    fn leading_dot() {
        assert!(OutputVersion::from_str(".1").is_err());
    }

    #[test]
    fn trailing_dot() {
        assert!(OutputVersion::from_str("1.").is_err());
    }

    #[test]
    fn one_int() {
        assert_eq!(OutputVersion::from_str("1").unwrap(), OutputVersion::new(1, 0, 0));
    }

    #[test]
    fn two_ints() {
        assert_eq!(OutputVersion::from_str("1.2").unwrap(), OutputVersion::new(1, 2, 0));
    }

    #[test]
    fn three_ints() {
        assert_eq!(OutputVersion::from_str("1.2.3").unwrap(), OutputVersion::new(1, 2, 3));
    }

    #[test]
    fn four_ints() {
        assert!(OutputVersion::from_str("1.2.3.4").is_err());
    }

    #[test]
    fn acceptable_if_same() {
        let a = OutputVersion::new(0, 0, 0);
        assert!(a.is_acceptable_for(a));
    }

    #[test]
    fn acceptable_if_newer_patch() {
        let wanted = OutputVersion::new(0, 0, 0);
        let actual = OutputVersion::new(0, 0, 1);
        assert!(actual.is_acceptable_for(wanted));
    }

    #[test]
    fn not_acceptable_if_older_patch() {
        let wanted = OutputVersion::new(0, 0, 1);
        let actual = OutputVersion::new(0, 0, 0);
        assert!(!actual.is_acceptable_for(wanted));
    }

    #[test]
    fn acceptable_if_newer_minor() {
        let wanted = OutputVersion::new(0, 0, 0);
        let actual = OutputVersion::new(0, 1, 0);
        assert!(actual.is_acceptable_for(wanted));
    }

    #[test]
    fn not_acceptable_if_older_minor() {
        let wanted = OutputVersion::new(0, 1, 0);
        let actual = OutputVersion::new(0, 0, 0);
        assert!(!actual.is_acceptable_for(wanted));
    }

    #[test]
    fn not_acceptable_if_newer_major() {
        let wanted = OutputVersion::new(0, 0, 0);
        let actual = OutputVersion::new(1, 0, 0);
        assert!(!actual.is_acceptable_for(wanted));
    }

    #[test]
    fn not_acceptable_if_older_major() {
        let wanted = OutputVersion::new(1, 0, 0);
        let actual = OutputVersion::new(0, 0, 0);
        assert!(!actual.is_acceptable_for(wanted));
    }
}
