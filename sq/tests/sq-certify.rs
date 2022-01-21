use std::fs::File;
use std::time;
use std::time::Duration;

use assert_cli::Assert;
use assert_cmd::Command;
use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use openpgp::Result;
use openpgp::cert::prelude::*;
use openpgp::KeyHandle;
use openpgp::packet::signature::subpacket::NotationData;
use openpgp::packet::signature::subpacket::NotationDataFlags;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;

const P: &StandardPolicy = &StandardPolicy::new();

#[test]
fn sq_certify() -> Result<()> {
    let tmp_dir = TempDir::new().unwrap();
    let alice_pgp = tmp_dir.path().join("alice.pgp");
    let bob_pgp = tmp_dir.path().join("bob.pgp");

    let (alice, _) =
        CertBuilder::general_purpose(None, Some("alice@example.org"))
        .generate()?;
    let mut file = File::create(&alice_pgp)?;
    alice.as_tsk().serialize(&mut file)?;

    let (bob, _) =
        CertBuilder::general_purpose(None, Some("bob@example.org"))
        .generate()?;
    let mut file = File::create(&bob_pgp)?;
    bob.serialize(&mut file)?;


    // A simple certification.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob@example.org",
            ])
        .stdout().satisfies(|output| {
            let cert = Cert::from_bytes(output).unwrap();
            let vc = cert.with_policy(P, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);
                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), None);
                    assert_eq!(c.regular_expressions().count(), 0);
                    assert_eq!(c.revocable().unwrap_or(true), true);
                    assert_eq!(c.exportable_certification().unwrap_or(true), true);
                    // By default, we set a duration.
                    assert!(c.signature_validity_period().is_some());

                    return true;
                }
            }

            false
        },
                            "Bad certification")
        .unwrap();

    // No expiry.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob@example.org",
              "--expires", "never"
            ])
        .stdout().satisfies(|output| {
            let cert = Cert::from_bytes(output).unwrap();
            let vc = cert.with_policy(P, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);
                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), None);
                    assert_eq!(c.regular_expressions().count(), 0);
                    assert_eq!(c.revocable().unwrap_or(true), true);
                    assert_eq!(c.exportable_certification().unwrap_or(true), true);
                    assert!(c.signature_validity_period().is_none());

                    return true;
                }
            }

            false
        },
                            "Bad certification")
        .unwrap();

    // Have alice certify bob@example.org for 0xB0B.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob@example.org",
              "--depth", "10",
              "--amount", "5",
              "--regex", "a",
              "--regex", "b",
              "--local",
              "--non-revocable",
              "--expires-in", "1d",
            ])
        .stdout().satisfies(|output| {
            let cert = Cert::from_bytes(output).unwrap();
            let vc = cert.with_policy(P, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);
                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), Some((10, 5)));
                    assert_eq!(&c.regular_expressions().collect::<Vec<_>>()[..],
                               &[ b"a", b"b" ]);
                    assert_eq!(c.revocable(), Some(false));
                    assert_eq!(c.exportable_certification(), Some(false));
                    assert_eq!(c.signature_validity_period(),
                               Some(Duration::new(24 * 60 * 60, 0)));

                    return true;
                }
            }

            false
        },
                            "Bad certification")
        .unwrap();

    // It should fail if the User ID doesn't exist.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob",
            ])
        .fails()
        .unwrap();

    // With a notation.
    Assert::cargo_binary("sq")
        .with_args(
            &["certify",
              "--notation", "foo", "bar",
              "--notation", "!foo", "xyzzy",
              "--notation", "hello@example.org", "1234567890",
              alice_pgp.to_str().unwrap(),
              bob_pgp.to_str().unwrap(),
              "bob@example.org",
            ])
        .stdout().satisfies(|output| {
            let cert = Cert::from_bytes(output).unwrap();

            // The standard policy will reject the
            // certification, because it has an unknown
            // critical notation.
            let vc = cert.with_policy(P, None).unwrap();
            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    assert_eq!(ua.bundle().certifications().len(), 1);
                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 0);
                }
            }

            // Accept the critical notation.
            let p = &mut StandardPolicy::new();
            p.good_critical_notations(&["foo"]);
            let vc = cert.with_policy(p, None).unwrap();

            for ua in vc.userids() {
                if ua.userid().value() == b"bob@example.org" {
                    // There should be a single signature.
                    assert_eq!(ua.bundle().certifications().len(), 1);

                    let certifications: Vec<_>
                        = ua.certifications().collect();
                    assert_eq!(certifications.len(), 1);

                    let c = certifications[0];

                    assert_eq!(c.trust_signature(), None);
                    assert_eq!(c.regular_expressions().count(), 0);
                    assert_eq!(c.revocable().unwrap_or(true), true);
                    assert_eq!(c.exportable_certification().unwrap_or(true), true);
                    // By default, we set a duration.
                    assert!(c.signature_validity_period().is_some());

                    let hr = NotationDataFlags::empty().set_human_readable();
                    let notations = &mut [
                        (NotationData::new("foo", "bar", hr.clone()), false),
                        (NotationData::new("foo", "xyzzy", hr.clone()), false),
                        (NotationData::new("hello@example.org", "1234567890", hr), false)
                    ];

                    for n in c.notation_data() {
                        if n.name() == "salt@notations.sequoia-pgp.org" {
                            continue;
                        }

                        for (m, found) in notations.iter_mut() {
                            if n == m {
                                assert!(!*found);
                                *found = true;
                            }
                        }
                    }
                    for (n, found) in notations.iter() {
                        assert!(found, "Missing: {:?}", n);
                    }

                    return true;
                }
            }

            false
        },
                            "Bad certification")
        .unwrap();

    Ok(())
}

#[test]
fn sq_certify_creation_time() -> Result<()>
{
    // $ date +'%Y%m%dT%H%M%S%z'; date +'%s'
    let iso8601 = "20220120T163236+0100";
    let t = 1642692756;
    let t = time::UNIX_EPOCH + time::Duration::new(t, 0);

    let dir = TempDir::new()?;

    let gen = |userid: &str| {
        let builder = CertBuilder::new()
            .add_signing_subkey()
            .set_creation_time(t)
            .add_userid(userid);
        builder.generate().map(|(key, _rev)| key)
    };

    // Alice certifies bob's key.

    let alice = "<alice@example.org>";
    let alice_key = gen(alice)?;

    let alice_pgp = dir.path().join("alice.pgp");
    {
        let mut file = File::create(&alice_pgp)?;
        alice_key.as_tsk().serialize(&mut file)?;
    }

    let bob = "<bob@other.org>";
    let bob_key = gen(bob)?;

    let bob_pgp = dir.path().join("bob.pgp");
    {
        let mut file = File::create(&bob_pgp)?;
        bob_key.serialize(&mut file)?;
    }

    // Build up the command line.
    let mut cmd = Command::cargo_bin("sq")?;
    cmd.args(["certify",
              &alice_pgp.to_string_lossy(),
              &bob_pgp.to_string_lossy(), bob,
              "--time", iso8601 ]);

    let assertion = cmd.assert().try_success()?;
    let stdout = String::from_utf8_lossy(&assertion.get_output().stdout);

    let cert = Cert::from_bytes(&*stdout)?;

    let vc = cert.with_policy(P, t)?;

    assert_eq!(vc.primary_key().creation_time(), t);

    let mut userid = None;
    for u in vc.userids() {
        if u.userid().value() == bob.as_bytes() {
            userid = Some(u);
            break;
        }
    }

    if let Some(userid) = userid {
        let certifications: Vec<_> = userid.certifications().collect();
        assert_eq!(certifications.len(), 1);
        let certification = certifications.into_iter().next().unwrap();

        assert_eq!(certification.get_issuers().into_iter().next(),
                   Some(KeyHandle::from(alice_key.fingerprint())));

        assert_eq!(certification.signature_creation_time(), Some(t));
    } else {
        panic!("missing user id");
    }

    Ok(())
}
