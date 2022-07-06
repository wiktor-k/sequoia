//! Data types for output format and format version choice.
//!
//! These data types express the values of the `--output-format` and
//! `--output-version` global options to `sq`.

use std::fmt;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use serde::Serialize;

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
