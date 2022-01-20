use std::time;

use assert_cmd::Command;
use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;

mod integration {
    use super::*;

    const P: &StandardPolicy = &StandardPolicy::new();

    #[test]
    fn sq_key_generate_creation_time() -> Result<()>
    {
        // $ date +'%Y%m%dT%H%M%S%z'; date +'%s'
        let iso8601 = "20220120T163236+0100";
        let t = 1642692756;

        let dir = TempDir::new()?;
        let key_pgp = dir.path().join("key.pgp");

        // Build up the command line.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args(["key", "generate",
                  "--creation-time", iso8601,
                  "--expires", "never",
                  "--export", &*key_pgp.to_string_lossy()]);

        cmd.assert().success();

        let result = Cert::from_file(key_pgp)?;
        let vc = result.with_policy(P, None)?;

        assert_eq!(vc.primary_key().creation_time(),
                   time::UNIX_EPOCH + time::Duration::new(t, 0));
        assert!(vc.primary_key().key_expiration_time().is_none());

        Ok(())
    }
}
