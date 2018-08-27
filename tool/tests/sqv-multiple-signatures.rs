extern crate assert_cli;

use assert_cli::Assert;

fn p(filename: &str) -> String {
    format!("../openpgp/tests/data/{}", filename)
}

/// Asserts that multiple signatures from the same TPK are properly
/// ignored.
#[test]
fn ignore_multiple_signatures() {
    // Check that all signatures are ok and accounted for.
    Assert::cargo_binary("sqv")
        .with_args(
            &["-r",
              &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
              "--signatures=2",
              "--accept-multiple-signatures",
              &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig.two-keys"),
              &p("messages/a-cypherpunks-manifesto.txt")])
         .unwrap();


    // Multiple signatures from the same TPK are ignored, and fails to
    // meet the threshold.
    Assert::cargo_binary("sqv")
        .with_args(
            &["-r",
              &p("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
              "--signatures=2",
              &p("messages/a-cypherpunks-manifesto.txt.ed25519.sig.duplicated"),
              &p("messages/a-cypherpunks-manifesto.txt")])
        .fails()
        .unwrap();
}
