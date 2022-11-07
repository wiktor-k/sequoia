This is a checklist for doing Sequoia releases:

  1. Decide which component to release, we'll call it `FOO`.
  1. Decide on the new version number `XXX`.
  1. Starting from `origin/main`, create a branch `staging` for the release.
  1. Bump `version = "XXX"` in `FOO/Cargo.toml`
  1. For all 'Cargo.toml's: Bump intra-workspace dependencies if
     necessary.
       - For instance, if releasing `sequoia-openpgp` and `sq` depends
         on features that are being released, then bump the dependency
         in `sq/Cargo.toml`.
  1. Run `cargo check` (this implicitly updates `Cargo.lock`)
  1. Commit changes to `Cargo.toml` and `Cargo.lock`.
  1. Update dependencies and run tests.
       - Use the exact Rust toolchain version of the current Sequoia
         MSRV (refer to `README.md`):  `rustup default 1.xx`
       - Run `cargo update` to update the dependencies.  If some
         dependency is updated and breaks due to our MSRV, find a good
         version of that dependency and select it using e.g. 'cargo
         update -p backtrace --precise  -3.46'.
       - Run 'make -f .Makefile check'.
  1. If releasing `sequoia-openpgp`, update
     https://sequoia-pgp.org/tmp/stats.txt by running:
      - `cargo run -p sequoia-openpgp --example statistics --release -- .../sks-dump-*.pgp > /tmp/stats.txt`
      - `cp /tmp/stats.txt sequoia@sequoia-pgp.org:sequoia-pgp.org/tmp`
  1. If releasing sq, update the manpage:
      - Clone https://gitlab.com/sequoia-pgp/manpage-maker to a
        separate location.
      - Add symlinks and run as described in the manpage-maker's readme
      - Copy man-sq*/*.1 to sequoia/sq/man-sq*
      - Make a commit with the message "sq, sqv: Update manpage."
  1. Make a commit with the message `FOO: Release XXX.`.
       - Push this to gitlab as `staging`, create a merge
         request, wait for CI.
  1. Make sure `cargo publish` works:
       - `mkdir /tmp/sequoia-staging`
       - `cd /tmp/sequoia-staging`
       - `git clone git@gitlab.com:sequoia-pgp/sequoia.git`
       - `cd sequoia`
       - `git checkout origin/staging`
       - `cargo publish -p FOO --dry-run`
  1. Wait until CI and `cargo publish -p FOO --dry-run` are successful.  In
     case of errors, correct them, and go back to the step creating
     the release commit.
  1. Merge the merge request
  1. Run `cargo publish -p FOO`
  1. Make a tag `FOO/vXXX` with the message `FOO: Release XXX.` signed
     with an offline key, which has been certified by our
     `openpgp-ca@sequoia-pgp.org` key.
  1. Push the signed tag `FOO/vXXX`.
  1. Regenerate `docs.sequoia-pgp.org`.
       - `cd /tmp/sequoia-staging`
       - `git clone git@gitlab.com:sequoia-pgp/docs.sequoia-pgp.org.git`
       - `cd docs.sequoia-pgp.org`
       - `make deploy`
  1. Announce the release.
       - IRC
       - mailing list (`devel@lists.sequoia-pgp.org`)
       - web site
