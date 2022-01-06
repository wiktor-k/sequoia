use std::fs::File;
use std::io::Write;

use anyhow::Context;
use assert_cmd::Command;
use chrono::prelude::*;
use chrono::Duration;
use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::parse::Parse;
use openpgp::Packet;
use openpgp::PacketPile;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;
use openpgp::types::ReasonForRevocation;
use openpgp::types::RevocationStatus;

const TRACE: bool = false;

mod integration {
    use super::*;

    const _P: StandardPolicy = StandardPolicy::new();
    const P: &StandardPolicy = &_P;

    fn t(reason: ReasonForRevocation,
         reason_message: &str,
         stdin: bool,
         third_party: bool,
         notations: &[(&str, &str)],
         time: Option<DateTime<Utc>>) -> Result<()>
    {
        // Round it down to a whole second to match the resolution of
        // OpenPGP's timestamp.
        let time = time.map(|t| {
            t - Duration::nanoseconds(t.timestamp_subsec_nanos() as i64)
        });

        // We're going to revoke alice's certificate.  If we're doing
        // it via a third-party revocation, then bob is the revoker.
        // Otherwise, it's alice.
        let (alice, _) =
            CertBuilder::general_purpose(None, Some("alice@example.org"))
            .set_creation_time(
                time.map(|t| (t - Duration::hours(1)).into()))
            .generate()?;

        let (bob, _) =
            CertBuilder::general_purpose(None, Some("bob@example.org"))
            .set_creation_time(
                time.map(|t| (t - Duration::hours(1)).into()))
            .generate()?;


        let mut cert = Vec::new();
        alice.serialize(&mut cert)?;

        let mut revoker = Vec::new();
        if third_party {
            bob.as_tsk().serialize(&mut revoker)?;
        } else {
            alice.as_tsk().serialize(&mut revoker)?;
        }


        // Build up the command line.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.args([
            "revoke",
            "certificate",
            match reason {
                ReasonForRevocation::KeyCompromised => "compromised",
                ReasonForRevocation::KeyRetired => "retired",
                ReasonForRevocation::KeySuperseded => "superseded",
                ReasonForRevocation::Unspecified => "unspecified",
                _ => panic!("Invalid reason: {}", reason),
            },
            reason_message
        ]);

        let _tmp_dir = match (third_party, stdin) {
            (true, true) => {
                // cat cert | sq revoke --revocation-key third-party
                let dir = TempDir::new()?;

                cmd.write_stdin(cert);

                let revoker_pgp = dir.path().join("revoker.pgp");
                let mut file = File::create(&revoker_pgp)?;
                file.write_all(&revoker)?;

                cmd.args([
                    "--revocation-key",
                    &*revoker_pgp.to_string_lossy()
                ]);

                Some(dir)
            },
            (true, false) => { // third_party && ! stdin
                // sq revoke --certificate cert --revocation-key third-party
                let dir = TempDir::new()?;

                let cert_pgp = dir.path().join("cert.pgp");
                let mut file = File::create(&cert_pgp)?;
                file.write_all(&cert)?;

                cmd.args([
                    "--certificate",
                    &*cert_pgp.to_string_lossy()
                ]);

                let revoker_pgp = dir.path().join("revoker.pgp");
                let mut file = File::create(&revoker_pgp)?;
                file.write_all(&revoker)?;

                cmd.args([
                    "--revocation-key",
                    &*revoker_pgp.to_string_lossy()
                ]);

                Some(dir)
            },
            (false, true) => { // ! third_party && stdin
                // cat key | sq revoke
                cmd.write_stdin(revoker);

                None
            },
            (false, false) => { // ! third_party && ! stdin
                // sq revoke --certificate key
                let dir = TempDir::new()?;

                let key_pgp = dir.path().join("key.pgp");
                let mut file = File::create(&key_pgp)?;
                file.write_all(&revoker)?;

                cmd.args([
                    "--certificate",
                    &*key_pgp.to_string_lossy()
                ]);

                Some(dir)
            },
        };

        // Time.
        if let Some(t) = time {
            cmd.args([
                "--time",
                &t.format("%Y-%m-%dT%H:%M:%SZ").to_string()],
            );
        }

        // Notations.
        for (k, v) in notations {
            cmd.args(["--notation", k, v]);
        }

        if TRACE {
            eprintln!("Running: {:?}", cmd);
        }
        let assertion = cmd.assert().try_success()?;
        let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);

        // Pretty print 'sq revoke''s output for debugging purposes.
        if TRACE {
            let mut cmd = Command::cargo_bin("sq")?;
            cmd.args([ "inspect" ]);
            cmd.write_stdin(stdout.as_bytes());
            let assertion = cmd.assert().try_success()?;
            eprintln!("Result:\n{}",
                      String::from_utf8_lossy(&assertion.get_output().stdout));
        }

        // Get the revocation certificate.

        assert!(matches!(
            alice.with_policy(P, time.map(Into::into)).unwrap()
                .revocation_status(),
            RevocationStatus::NotAsFarAsWeKnow));

        let sig = if third_party {
            // We should get a certificate stub.
            let result = Cert::from_bytes(&*stdout)?;
            let status = result.with_policy(P, time.map(Into::into))?
                .revocation_status();
            if let RevocationStatus::CouldBe(sigs) = status {
                assert_eq!(sigs.len(), 1);
                let sig = sigs.into_iter().next().unwrap();

                // Bob issued the revocation.
                assert_eq!(sig.get_issuers().into_iter().next(),
                           Some(bob.fingerprint().into()));

                // Verify the revocation.
                sig.clone()
                    .verify_primary_key_revocation(
                        &bob.primary_key(),
                        &alice.primary_key())
                    .context("revocation is not valid")?;

                sig.clone()
            } else {
                panic!("Unexpected revocation status: {:?}", status);
            }
        } else {
            // We should get just a single signature packet.
            let pp = PacketPile::from_bytes(&*stdout)?;

            assert_eq!(pp.children().count(), 1,
                       "expected a single packet");

            if let Some(Packet::Signature(sig)) = pp.path_ref(&[0]) {
                // Alice issued the revocation.
                assert_eq!(sig.get_issuers().into_iter().next(),
                           Some(alice.fingerprint().into()));

                let alice2 = alice.insert_packets(sig.clone()).unwrap();

                // Verify the revocation.
                assert!(matches!(
                    alice2.with_policy(P, time.map(Into::into)).unwrap()
                        .revocation_status(),
                    RevocationStatus::Revoked(_)));

                sig.clone()
            } else {
                panic!("Expected a signature, got: {:?}", pp);
            }
        };

        // Revocation reason.
        assert_eq!(sig.typ(), SignatureType::KeyRevocation);
        assert_eq!(sig.reason_for_revocation(),
                   Some((reason, reason_message.as_bytes())));

        // Time.
        if let Some(t) = time {
            assert_eq!(Some(t.into()), sig.signature_creation_time());
        }

        // Notations.
        let got: Vec<(&str, String)> = sig.notation_data()
            .map(|n| {
                (n.name(),
                 String::from_utf8_lossy(n.value()).into())
            })
            .collect();

        for (n, v) in notations {
            assert!(got.contains(&(n, String::from(*v))),
                    "notations: {:?}\nexpected: {}: {}",
                    notations, n, v);
        }

        Ok(())
    }

    fn dispatch(reasons: &[ReasonForRevocation],
                msgs: &[&str],
                stdin: &[bool],
                third_party: &[bool],
                notations: &[&[(&str, &str)]],
                time: &[Option<DateTime<Utc>>]) -> Result<()>
    {
        for third_party in third_party {
            for time in time {
                for stdin in stdin {
                    for notations in notations {
                        for reason in reasons {
                            for msg in msgs {
                                eprintln!("\n\
                                           third party: {}\n\
                                           time: {:?}\n\
                                           stdin: {}\n\
                                           notations: {:?}\n\
                                           reason: {:?}\n\
                                           message: {:?}",
                                          third_party, time, stdin, notations,
                                          reason, msg);
                                t(*reason, *msg,
                                  *stdin, *third_party, *notations,
                                  *time)?;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    const REASONS: &[ ReasonForRevocation ] = &[
        ReasonForRevocation::KeyCompromised,
        ReasonForRevocation::KeyRetired,
        ReasonForRevocation::KeySuperseded,
        ReasonForRevocation::Unspecified
    ];
    const MSGS: &[&str] = &[
        "oh NO!",
        "Löwe 老\n虎 Léopard"
    ];
    const NOTATIONS: &[ &[ (&str, &str) ] ] = &[
        &[],
        &[("a", "b")],
        &[("a", "b"), ("hallo@sequoia-pgp.org", "VALUE")]
    ];

    #[test]
    fn sq_revoke_stdin() -> Result<()> {
        let now = Utc::now();

        dispatch(
            REASONS,
            MSGS,
            // stdin
            &[true],
            // third_party
            &[false],
            NOTATIONS,
            // time
            &[
                None,
                Some(now),
                Some(now - Duration::hours(1))
            ])
    }

    #[test]
    fn sq_revoke() -> Result<()> {
        let now = Utc::now();

        dispatch(
            REASONS,
            MSGS,
            // stdin
            &[false],
            // third_party
            &[false],
            NOTATIONS,
            // time
            &[
                None,
                Some(now),
                Some(now - Duration::hours(1))
            ])
    }

    #[test]
    fn sq_revoke_third_party_stdin() -> Result<()> {
        let now = Utc::now();

        dispatch(
            REASONS,
            MSGS,
            // stdin
            &[true],
            // third_party
            &[true],
            NOTATIONS,
            // time
            &[
                None,
                Some(now),
                Some(now - Duration::hours(1))
            ])
    }

    #[test]
    fn sq_revoke_third_party() -> Result<()> {
        let now = Utc::now();

        dispatch(
            REASONS,
            MSGS,
            // stdin
            &[false],
            // third_party
            &[true],
            NOTATIONS,
            // time
            &[
                None,
                Some(now),
                Some(now - Duration::hours(1))
            ])
    }
}
