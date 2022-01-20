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
use openpgp::packet::Key;
use openpgp::packet::UserID;
use openpgp::PacketPile;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::types::SignatureType;
use openpgp::types::ReasonForRevocation;
use openpgp::types::RevocationStatus;

const TRACE: bool = false;

mod integration {
    use super::*;

    const P: &StandardPolicy = &StandardPolicy::new();

    const ALICE: &str = "<alice@example.org>";

    #[derive(PartialEq, Eq)]
    enum Subcommand {
        Certificate,
        UserID(Vec<String>),
        Subkey,
    }

    impl Subcommand {
        fn userids(&self) -> &[String] {
            if let Subcommand::UserID(ref userids) = self {
                assert!(userids.len() > 0);
                userids
            } else {
                &[]
            }
        }
    }

    // If subkey is not None, then a subkey will be revoked.
    //
    // Otherwise, USERIDS is a vector of User IDs.  If it is empty,
    // then a default User ID will be used and the *certificate* will
    // be revoked.  If it contains at least one entry, then each entry
    // will be added as a User ID, and the last User ID will be
    // revoked.
    fn t(subcommand: &Subcommand,
         reason: ReasonForRevocation,
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

        let gen = |userids: &[&str]| {
            let mut builder = CertBuilder::new()
                .add_signing_subkey()
                .set_creation_time(
                    time.map(|t| (t - Duration::hours(1)).into()));
            for &u in userids {
                builder = builder.add_userid(u);
            }
            builder.generate().map(|(key, _rev)| key)
        };

        let mut userid: Option<&str> = None;
        let mut userids: Vec<&str> = vec![ ALICE ];

        if let Subcommand::UserID(_) = subcommand {
            userids = subcommand.userids().iter()
                .map(|u| u.as_str()).collect();
            userid = userids.last().map(|u| *u)
        }

        // We're going to revoke alice's certificate or a User ID.  If
        // we're doing it via a third-party revocation, then bob is
        // the revoker.  Otherwise, it's alice.
        let alice = gen(&userids)?;
        let bob = gen(&[ "<revoker@some.org>" ])?;

        let mut cert = Vec::new();
        alice.serialize(&mut cert)?;

        let mut revoker = Vec::new();
        if third_party {
            bob.as_tsk().serialize(&mut revoker)?;
        } else {
            alice.as_tsk().serialize(&mut revoker)?;
        }

        let subkey: Key<_, _> = alice.with_policy(P, None).unwrap()
            .keys().subkeys().nth(0).unwrap().key().clone();

        // Build up the command line.
        let mut cmd = Command::cargo_bin("sq")?;
        cmd.arg("revoke");
        if let Some(userid) = userid {
            cmd.args([
                "userid", userid,
                match reason {
                    ReasonForRevocation::UIDRetired => "retired",
                    ReasonForRevocation::Unspecified => "unspecified",
                    _ => panic!("Invalid reason: {}", reason),
                },
                reason_message
            ]);
        } else {
            match subcommand {
                Subcommand::Certificate => {
                    cmd.arg("certificate");
                }
                Subcommand::Subkey => {
                    cmd.args(&["subkey", &subkey.fingerprint().to_string()]);
                }
                Subcommand::UserID(_) => unreachable!(),
            }
            cmd.args([
                match reason {
                    ReasonForRevocation::KeyCompromised => "compromised",
                    ReasonForRevocation::KeyRetired => "retired",
                    ReasonForRevocation::KeySuperseded => "superseded",
                    ReasonForRevocation::Unspecified => "unspecified",
                    _ => panic!("Invalid reason: {}", reason),
                },
                reason_message
            ]);
        }

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

        {
            let vc = alice.with_policy(P, time.map(Into::into)).unwrap();
            assert!(matches!(vc.revocation_status(),
                             RevocationStatus::NotAsFarAsWeKnow));

            if let Some(userid) = userid {
                let mut found = false;
                for u in vc.userids() {
                    if u.value() == userid.as_bytes() {
                        assert!(matches!(u.revocation_status(),
                                         RevocationStatus::NotAsFarAsWeKnow));

                        found = true;
                        break;
                    }
                }
                assert!(found, "User ID {} not found on certificate", userid);
            }
        }

        // Get the revocation certificate.
        let sig = if ! third_party && subcommand == &Subcommand::Certificate {
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
        } else {
            // We should get a certificate stub.
            let result = Cert::from_bytes(&*stdout)?;

            let vc = result.with_policy(P, time.map(Into::into))?;

            // Make sure the certificate stub only contains the
            // revoked User ID (the rest should be striped).
            assert_eq!(vc.userids().count(), 1);

            // Get the revocation status of the revoked object.
            let status = match subcommand {
                Subcommand::Certificate => vc.revocation_status(),
                Subcommand::Subkey => {
                    let mut status = None;
                    for k in vc.keys() {
                        if k.fingerprint() == subkey.fingerprint() {
                            status = Some(k.revocation_status());
                            break;
                        }
                    }
                    if let Some(status) = status {
                        status
                    } else {
                        panic!("Revoked subkey {} not found on certificate",
                               subkey.fingerprint());
                    }
                }
                Subcommand::UserID(_) => {
                    let userid = userid.unwrap();
                    let mut status = None;
                    for u in vc.userids() {
                        if u.value() == userid.as_bytes() {
                            status = Some(u.revocation_status());
                            break;
                        }
                    }
                    if let Some(status) = status {
                        status
                    } else {
                        panic!("Revoked user ID {} not found on certificate",
                               userid);
                    }
                }
            };

            // Make sure the revocation status is sane.
            if third_party {
                if let RevocationStatus::CouldBe(sigs) = status {
                    assert_eq!(sigs.len(), 1);
                    let sig = sigs.into_iter().next().unwrap();

                    // Bob issued the revocation.
                    assert_eq!(sig.get_issuers().into_iter().next(),
                               Some(bob.fingerprint().into()));

                    // Verify the revocation.
                    match subcommand {
                        Subcommand::Certificate => {
                            sig.clone()
                                .verify_primary_key_revocation(
                                    &bob.primary_key(),
                                    &alice.primary_key())
                                .context("revocation is not valid")?;
                        }
                        Subcommand::Subkey => {
                            sig.clone()
                                .verify_subkey_revocation(
                                    &bob.primary_key(),
                                    &alice.primary_key(),
                                    &subkey)
                                .context("revocation is not valid")?;
                        }
                        Subcommand::UserID(_) => {
                            sig.clone()
                                .verify_userid_revocation(
                                    &bob.primary_key(),
                                    &alice.primary_key(),
                                    &UserID::from(userid.unwrap()))
                                .context("revocation is not valid")?;
                        }
                    }

                    sig.clone()
                } else {
                    panic!("Unexpected revocation status: {:?}", status);
                }
            } else {
                if let RevocationStatus::Revoked(sigs) = status {
                    assert_eq!(sigs.len(), 1);
                    let sig = sigs.into_iter().next().unwrap();

                    // Alice issued the revocation.
                    assert_eq!(sig.get_issuers().into_iter().next(),
                               Some(alice.fingerprint().into()));

                    // Since it is a self-siganture, sig has already
                    // been validated.

                    sig.clone()
                } else {
                    panic!("Unexpected revocation status: {:?}", status);
                }
            }
        };

        // Revocation reason.
        match subcommand {
            Subcommand::Certificate =>
                assert_eq!(sig.typ(), SignatureType::KeyRevocation),
            Subcommand::Subkey =>
                assert_eq!(sig.typ(), SignatureType::SubkeyRevocation),
            Subcommand::UserID(_) =>
                assert_eq!(sig.typ(), SignatureType::CertificationRevocation),
        }
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

    fn dispatch(subcommand: Subcommand,
                reasons: &[ReasonForRevocation],
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
                                t(&subcommand,
                                  *reason, *msg,
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

    const CERT_REASONS: &[ ReasonForRevocation ] = &[
        ReasonForRevocation::KeyCompromised,
        ReasonForRevocation::KeyRetired,
        ReasonForRevocation::KeySuperseded,
        ReasonForRevocation::Unspecified
    ];
    const USERID_REASONS: &[ ReasonForRevocation ] = &[
        ReasonForRevocation::UIDRetired,
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

    // User ID revocation tests.
    #[test]
    fn sq_revoke_cert_stdin() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::Certificate,
            CERT_REASONS,
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
    fn sq_revoke_cert() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::Certificate,
            CERT_REASONS,
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
    fn sq_revoke_cert_third_party_stdin() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::Certificate,
            CERT_REASONS,
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
    fn sq_revoke_cert_third_party() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::Certificate,
            CERT_REASONS,
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


    // Subkey revocation tests.
    //
    // We manually unroll to get some parallelism.  Otherwise, the
    // tests take way too long.
    #[test]
    fn sq_revoke_subkey_stdin() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::Subkey,
            CERT_REASONS,
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
    fn sq_revoke_subkey() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::Subkey,
            CERT_REASONS,
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
    fn sq_revoke_subkey_third_party_stdin() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::Subkey,
            CERT_REASONS,
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
    fn sq_revoke_subkey_third_party() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::Subkey,
            CERT_REASONS,
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

    // User ID revocation tests.
    //
    // We manually unroll to get some parallelism.  Otherwise, the
    // tests take way too long.
    #[test]
    fn sq_revoke_userid_stdin() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::UserID(vec![ ALICE.into() ]),
            USERID_REASONS,
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
    fn sq_revoke_userid() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::UserID(vec![ ALICE.into() ]),
            USERID_REASONS,
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
    fn sq_revoke_userid_third_party_stdin() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::UserID(vec![ ALICE.into() ]),
            USERID_REASONS,
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
    fn sq_revoke_userid_third_party() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::UserID(vec![ ALICE.into() ]),
            USERID_REASONS,
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


    #[test]
    fn sq_revoke_one_of_three_userids() -> Result<()> {
        let now = Utc::now();

        dispatch(
            Subcommand::UserID(vec![
                "<alice@example.org".into(),
                "<alice@some.org>".into(),
                "<alice@other.org>".into(),
            ]),
            USERID_REASONS,
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
}
