---
title: "Sequoia-PGP sq"
subtitle: "integration tests, requirements, acceptance criteria"
author: "The Sequoia-PGP project"
template: rust
bindings:
- subplot/sq-subplot.yaml
- lib/files.yaml
- lib/runcmd.yaml
functions:
- subplot/sq-subplot.rs
...

# Introduction

The [Sequoia-PGP][] project is an implementation of the [OpenPGP][]
standard for encryption and digital signatures. Sequoia itself is a
library for the Rust programming language, as well as the `sq` command
line tool for people to use directly. This document captures the
requirements and acceptance criteria for the `sq` tool and how they
are verified, and at the same time acts as an integration test for the
tool.

[Sequoia-PGP]: https://sequoia-pgp.org/
[OpenPGP]: https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP


## Testing approach for sq

This document explicitly only covers integration and acceptance
testing of the `sq` command line tool. It does not try to verify that
the underlying library implements OpenPGP correctly: the library has
its own test suite for that. Instead, this document concentrates on
making sure the `sq` command line tool behaves as it should from an
end-user's point of view.

We make the following simplifying assumption: we know the `sq`
developers as competent developers, and assume that they don't
entangle unrelated functionality. By this we mean that we feel we can
assume that the code in `sq` that reads input files is separate from the
code that compresses it, which in turn is independent of the code that
writes output as text or binary data. Thus, we verify each such
functionality independently of each other. This drastically cuts down
the number of feature combinations we need to test. If this assumption
turns out to be incorrect, we will rethink and revise the testing
approach as needed.

We also know, by inspection, that `sq` uses the well-known,
well-respected Rust library `clap` for parsing the command line.
Because of this we feel it's not necessary to verify that, for
example, `sq` notices that a required argument is missing from the
command line, or that it notices that there are extra arguments
present. We will concentrate on testing that when invoked with valid
arguments results in expected output.

## Using Subplot and this document

The acceptance criteria and requirements are explained in prose and
when they can be verified in an automated way, that is done using
_test scenarios_. Both the prose and the scenarios are meant to be
understood and agreed to by all stakeholders in the project.

The [Subplot][] tool is used to render this document into
human-readable form (HTML or PDF), and to generate a test program that
executes the scenarios and checks they all pass.

To achieve this, run the following commands:

~~~sh
$ git clone https://gitlab.com/sequoia-pgp/sequoia.git
$ cd sequoia/sq
$ subplot docgen sq-subplot.md -o sq-subplot.html
$ subplot docgen sq-subplot.md -o sq-subplot.pdf
$ cargo test
~~~

If you only care about generating and running tests, you only need to
run `cargo test`. All the dependencies for that are automatically
handled via `Cargo.toml`.

To generate typeset documents (HTML and PDF), you need the following
software installed:

* [Subplot][], via cargo install or a Debian package (see its website)
* Pandoc
* Parts of TeX Live (for PDF)
* Graphviz

On a Debian system, that means the following packages:

> `subplot pandoc pandoc-citeproc lmodern librsvg2-bin graphviz
> texlive-latex-base texlive-latex-recommended
> texlive-fonts-recommended plantuml`

[Subplot]: https://subplot.liw.fi/

# Smoke test

_Requirement: We must be able to invoke `sq` at all._

This scenario verifies that we can run `sq` in the simplest possible
case: we ask the program for its version. If this works, then we know
that the executable program exists, can be invoked, and at least some
of its command line parsing code works. If this scenario doesn't work,
then we can't expect anything else to work either.

~~~scenario
given an installed sq
when I run sq --version
then exit code is 0
then stdout matches regex ^sq \d+\.\d+\.\d+ .*$
~~~

# Key management: `sq key`

This chapter covers all key management functionality: the `sq key`
subcommands.

## Key generation: `sq key generate`

This section covers key generation with `sq`. Keys are somewhat
complicated: it is possible to have keys for specify that they can
only used for specific operations, or the time period when they are
valid. Different cryptographic algorithms have different kinds of
keys. We verify these by varying what kind keys we generate and that
they look as expected, when inspected.

### Generate a key with defaults

_Requirement: We must be able to generate new encryption keys and
corresponding certificates._

This scenario generates a new key with `sq` using default settings and
inspects it to see if it looks at least vaguely correct. Note that in
this scenario we don't verify that the key works, other scenarios take
care of that. Here we merely verify that the new key looks OK.

~~~scenario
given an installed sq
when I run sq key generate --userid Tomjon --export tomjon.pgp
when I run sq inspect tomjon.pgp
then stdout contains "Tomjon"
then stdout contains "Expiration time: 20"
then stdout contains "Key flags: certification"
then stdout contains "Key flags: signing"
then stdout contains "Key flags: transport encryption, data-at-rest encryption"
~~~

### Generate key without user identifiers

_Requirement: We must be able to generate new encryption keys without
any user identifiers._

~~~scenario
given an installed sq
when I run sq key generate --export key.pgp
then file key.pgp contains "-----BEGIN PGP PRIVATE KEY BLOCK-----"
~~~


### Generate key with more than one user identifier

_Requirement: We must be able to generate new encryption keys with
more than one user identifier._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --userid '<alice@example.com>' --export key.pgp
then file key.pgp contains "Comment: Alice"
then file key.pgp contains "Comment: <alice@example.com>"
~~~


### Generate a key for encryption only

_Requirement: We must be able to generate a key that can only be used
for encryption, and can't be used for signing._

Note that `sq` always creates a key usable for certification.

~~~scenario
given an installed sq
when I run sq key generate --cannot-sign --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout doesn't contain "Key flags: signing"
then stdout contains "Key flags: transport encryption, data-at-rest encryption"
~~~

### Generate a key for storage encryption only

_Requirement: We must be able to generate a key that can only be used
for at-rest (storage) encryption._

~~~scenario
given an installed sq
when I run sq key generate --can-encrypt=storage --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout doesn't contain "transport encryption"
then stdout contains "Key flags: data-at-rest encryption"
~~~

### Generate a key for transport encryption only

_Requirement: We must be able to generate a key that can only be used
for transport encryption._

~~~scenario
given an installed sq
when I run sq key generate --can-encrypt=transport --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout contains "Key flags: transport encryption"
then stdout doesn't contain "data-at-rest encryption"
~~~

### Generate a key for signing only

_Requirement: We must be able to generate a key that can only be used
for signing, and can't be used for encryption._

~~~scenario
given an installed sq
when I run sq key generate --cannot-encrypt --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout contains "Key flags: signing"
then stdout doesn't contain "Key flags: transport encryption, data-at-rest encryption"
~~~

### Generate an elliptic curve key

_Requirement: We must be able to generate an Curve25519 key_

This is currently the default key, but we check it separately in case
the default ever changes.

~~~scenario
given an installed sq
when I run sq key generate --cipher-suite=cv25519 --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Public-key algo: EdDSA Edwards-curve Digital Signature Algorithm"
then stdout contains "Public-key size: 256 bits"
~~~

### Generate a three kilobit RSA key

_Requirement: We must be able to generate a 3072-bit RSA key._

~~~scenario
given an installed sq
when I run sq key generate --cipher-suite=rsa3k --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Public-key algo: RSA"
then stdout contains "Public-key size: 3072 bits"
~~~

### Generate four kilobit RSA key

_Requirement: We must be able to generate a 4096-bit RSA key._

~~~scenario
given an installed sq
when I run sq key generate --cipher-suite=rsa4k --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Public-key algo: RSA"
then stdout contains "Public-key size: 4096 bits"
~~~

### Generate a key with revocation certificate

_Requirement: We must be able to specify where the revocation
certificate is store._

When `sq` generates a key, it also generates a revocation certificate.
By default, this is written to a file next to the key file. However,
we need to able to specify where it goes. This scenario tests various
cases.

~~~scenario
given an installed sq
when I run sq key generate --export key.pgp
then file key.pgp.rev contains "Comment: Revocation certificate for"

when I run sq key generate --export key2.pgp --rev-cert rev.pgp
then file rev.pgp contains "Comment: Revocation certificate for"
~~~

### Generate a key with default duration

_Requirement: By default, generated key expire._

We generate a key with defaults, and check the key expires.

~~~scenario
given an installed sq
when I run sq key generate --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Expiration time: 20"
~~~

The check for expiration time assumes the scenario is run the 21st
century, and will need to be amended in the 2090s or by time
travellers running it before about the year 2000.

### Generate a key that expires at a given moment

_Requirement: We must be able to generate a key that expires._

Note that the timestamp given to `--expire` is the first second when
the key is no longer valid, not the last second it's valid. The
inspect output is the last second of validity.

~~~scenario
given an installed sq
when I run sq key generate --expires=2038-01-19T03:14:07+00:00 --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Expiration time: 2038-01-19 03:14:06 UTC"
~~~

### Generate a key with a given duration

_Requirement: We must be able to generate a key that expires in a
given time._

~~~scenario
given an installed sq
when I run sq key generate --expires-in=1y --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Expiration time: 20"
~~~

### Generate a key without password

_Requirement: We must be able to generate a that doesn't have a
password._

~~~scenario
given an installed sq
when I run sq key generate --export key.pgp
when I run sq inspect key.pgp
then stdout contains "Secret key: Unencrypted"
~~~

### Generate a key with a password

_Requirement: We must be able to generate a that does have a
password._

Unfortunately, the `--with-password` option causes `sq` to read the
password from the terminal, and that makes it hard to do in an
automated test. Thus, this scenario isn't enabled, waiting for a way
to feed `sq` a password as if the user typed it from a terminal.

~~~
given an installed sq
when I run sq key generate --export key.pgp --with-password
when I run sq inspect key.pgp
then stdout contains "Secret key: Encrypted"
~~~

## Certificate extraction: `sq key extract-cert`

This section covers extraction of certificates from keys: the `sq key
extract-certificate` subcommand and its variations.


### Extract certificate to the standard output

_Requirement: We must be able to extract a certificate to standard
output._

~~~scenario
given an installed sq
when I run sq key generate --export key.pgp
when I run sq key extract-cert key.pgp
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then stdout contains "-----END PGP PUBLIC KEY BLOCK-----"
~~~


### Extract certificate to a file

_Requirement: We must be able to extract a certificate to a named
file._

~~~scenario
given an installed sq
when I run sq key generate --export key.pgp
when I run sq key extract-cert key.pgp -o cert.pgp
then file cert.pgp contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then file cert.pgp contains "-----END PGP PUBLIC KEY BLOCK-----"
~~~


### Extract binary certificate to the standard output

_Requirement: We must be able to extract a binary certificate to the
standard output._

This scenario actually only verifies the output doesn't look like a
textual certificate. It could certainly be improved.

~~~scenario
given an installed sq
when I run sq key generate --export key.pgp
when I run sq key extract-cert key.pgp --binary
then stdout doesn't contain "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then stdout doesn't contain "-----END PGP PUBLIC KEY BLOCK-----"
~~~


### Extract binary certificate from the standard input

_Requirement: We must be able to extract a certificate from a key read
from the standard input._

Unfortunately, Subplot does not currently have a way to redirect
stding from a file. This scenario is inactive and here as a
placeholder until Subplot learns a new trick.

~~~
given an installed sq
when I run sq key generate --export key.pgp
when I run sq key extract-cert < key.pgp
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then stdout contains "-----END PGP PUBLIC KEY BLOCK-----"
~~~


# Keyring management: `sq keyring`

This chapter verifies that the various subcommands to manage keyring
files work: subcommands of the `sq keyring` command.

## Joining keys into a keyring: `sq keyring join`

The scenarios in this section verify that various ways of joining keys
into a keyring work.

### Join two keys into a textual keyring to stdout

_Requirement: we can join two keys into a keyring, and have it written
to stdout._

This is for secret keys, with the output going to stdout in text form.

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then stdout contains "-----END PGP PUBLIC KEY BLOCK-----"
~~~

### Join two keys into a textual keyring to a named file

_Requirement: we can join two keys into a keyring, and have it written
to a named file._

This is for secret keys, with the output going to a file in text form.

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
then file ring.pgp contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then file ring.pgp contains "-----END PGP PUBLIC KEY BLOCK-----"
when I run sq inspect ring.pgp
then stdout contains "Transferable Secret Key."
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### Join two keys into a binary keyring

_Requirement: we can join two keys into a keyring in binary form._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp --binary
when I try to run grep PGP ring.pgp
then command fails
when I run sq inspect ring.pgp
then stdout contains "Transferable Secret Key."
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### Join two certificates into a keyring

_Requirement: we can join two certificates into a keyring._

This scenario writes the keyring to a named file. We assume the
writing operation is independent of the types of items in the keyring,
so we don't change writing to stdout separately.

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq key extract-cert alice.pgp -o alice-cert.pgp
when I run sq key extract-cert bob.pgp -o bob-cert.pgp
when I run sq keyring join alice-cert.pgp bob-cert.pgp -o ring.pgp
when I run cat ring.pgp
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then stdout contains "-----END PGP PUBLIC KEY BLOCK-----"
when I run sq inspect ring.pgp
then stdout doesn't contain "Transferable Secret Key."
then stdout contains "OpenPGP Certificate."
then stdout contains "Alice"
then stdout contains "Bob"
~~~

## Filter a keyring: `sq keyring filter`

The scenarios in this section verify that various ways of filtering
the contents of a keyring work: the `sq keyring filter` subcommand
variants.

### We can extract only certificates to named file

_Requirement: we can remove private keys from a keyring, leaving only
certificates._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring filter --to-cert ring.pgp -o filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "OpenPGP Certificate."
then stdout doesn't contain "Transferable Secret Key."
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### We can filter to stdout

_Requirement: we can get filter output to stdout instead of a named
file._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring filter --to-cert ring.pgp
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then stdout contains "-----END PGP PUBLIC KEY BLOCK-----"
~~~

### We can filter with binary output

_Requirement: we can get filter output in binary form._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring filter --binary --to-cert ring.pgp
then stdout doesn't contain "-----BEGIN PGP PUBLIC KEY BLOCK-----"
~~~

### We can keep only matching certificates

_Requirement: we can remove certificates that don't match filter
criteria._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --userid Bob --export alice.pgp
when I run sq keyring filter --prune-certs --name Alice alice.pgp -o filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### We can filter for specific user id

_Requirement: we can extract only keys and certificates with a
specific user id._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring filter --userid Alice ring.pgp -o filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### We can filter for any of several user ids

_Requirement: we can extract only keys and certificates with any of
specific user ids._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring filter --userid Alice --userid Bob ring.pgp -o filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### We can filter for a name

_Requirement: we can extract only keys and certificates with a name as
part of a user ids._

~~~scenario
given an installed sq
when I run sq key generate --userid 'Alice <alice@example.com>' --export alice.pgp
when I run sq key generate --userid 'Bob <bob@example.com>' --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring filter --name Alice ring.pgp -o filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### We can filter for several names

_Requirement: we can extract only keys and certificates with any of
several names as part of the user id._

~~~scenario
given an installed sq
when I run sq key generate --userid 'Alice <alice@example.com>' --export alice.pgp
when I run sq key generate --userid 'Bob <bob@example.com>' --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring filter --name Alice --name Bob ring.pgp -o filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### We can filter for a domain

_Requirement: we can extract only keys and certificates with a name as
part of a user ids._

~~~scenario
given an installed sq
when I run sq key generate --userid 'Alice <alice@example.com>' --export alice.pgp
when I run sq key generate --userid 'Bob <bob@sequoia-pgp.org>' --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring filter --domain example.com ring.pgp -o filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### We can filter for several domains

_Requirement: we can extract only keys and certificates with any of
several names as part of the user id._

~~~scenario
given an installed sq
when I run sq key generate --userid 'Alice <alice@example.com>' --export alice.pgp
when I run sq key generate --userid 'Bob <bob@sequoia-pgp.org>' --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring filter --domain example.com --domain sequoia-pgp.org ring.pgp -o filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout contains "Bob"
~~~

## Listing contents of a keyring: `sq keyring list`

The scenarios in this section verify the contents of a keyring can be listed.

### List keys in a keyring

_Requirement: we can list the keys in a keyring._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring list ring.pgp
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### List keys in a key file

_Requirement: we can list the keys in a key file._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq keyring list alice.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### List all user ids in a key file

_Requirement: we can list all user ids._

~~~scenario
given an installed sq
when I run sq key generate --userid Alice --userid Bob --export alice.pgp
when I run sq keyring list alice.pgp --all-userids
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### List keys in keyring read from stdin

_Requirement: we can list keys in a keyring that we read from stdin._

This isn't implemented yet, because Subplot needs to add support for
redirecting stdin to come from a file first.


## Split a keyring: `sq keyring split`

The scenarios in this section verify that splitting a keyring into
individual files, one per key: the `sq keyring split` subcommand.

Or rather, there will be such scenarios here when Subplot provides
tools for dealing with randomly named files. Until then, this section
is a placeholder.

~~~
given an installed sq
when I run sq key generate --userid Alice --export alice.pgp
when I run sq key generate --userid Bob --export bob.pgp
when I run sq keyring join alice.pgp bob.pgp -o ring.pgp
when I run sq keyring split ring.pgp
then the resulting files match alice,pgp and bob.pgp
~~~

# Encrypt and decrypt a file using public keys

_Requirement: We must be able to encrypt a file using a certificate,
and then decrypt it using the corresponding key._

This scenario creates a plain text file, generates a key, encrypts and
then decrypts the file. The resulting output must be identical to the
original plain text input file. This is a very simplistic scenario and
does not even try to test harder cases (binary files, very large
files, etc).

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --userid Tomjon --export tomjon.pgp
when I run sq key extract-cert -o cert.pgp tomjon.pgp
when I run sq encrypt -o e.pgp --recipient-cert cert.pgp hello.txt
when I run sq decrypt -o output.txt --recipient-key tomjon.pgp e.pgp
then files hello.txt and output.txt match
~~~

# Sign a document and verify the signature

_Requirement: We must be able to sign a document, to prove it comes
from us. We must be able to verify a signature on a document._

We break this into three scenarios. One that uses a binary signature,
one with textual cleartext signature, and one with a detached
signature.

## Binary signature

This scenario creates a small text file, and signs it, and checks that
the signature is OK.

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --userid Tomjon --export tomjon.pgp
when I run sq sign -o s.pgp --signer-key tomjon.pgp hello.txt
then file s.pgp contains "-----BEGIN PGP MESSAGE-----"
then file s.pgp contains "-----END PGP MESSAGE-----"
when I run sq verify -o output.txt --signer-cert tomjon.pgp s.pgp
then files hello.txt and output.txt match
then file output.txt contains "hello, world"
~~~

However, if the signed file is modified, verification must fail. We
check this by removing a line from the signed file, which is a crude
way of making sure the signature doesn't match.

Further, the output must not contain the input if the verification
fails. This is to prevent accidents where the user is shown unverified
text, and possibly a warning that it's not to be trusted, but they
make use of the text anyway.

~~~scenario
when I run sed -i 3d s.pgp
when I try to run sq verify --signer-cert tomjon.pgp s.pgp
then exit code is not 0
then stdout doesn't contain "hello, world"
~~~


## Cleartext signature

This scenario is essentially the same, but uses a cleartext signature,
and the way the signed file is mangled is different.

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --userid Tomjon --export tomjon.pgp
when I run sq sign --cleartext-signature -o s.pgp --signer-key tomjon.pgp hello.txt
then file s.pgp contains "hello, world"
when I run sq verify -o output.txt --signer-cert tomjon.pgp s.pgp
then files hello.txt and output.txt match
then file output.txt contains "hello, world"
~~~

We modify the signed file by converting the actual message embedded in
the signed file to upper case, which is easy to do, as it's in cleartext.

~~~scenario
when I run sed -i 's/^hello, world/HELLO, WORLD/' s.pgp
when I try to run sq verify --signer-cert tomjon.pgp s.pgp
then exit code is 1
then stdout doesn't contain "hello, world"
then stdout doesn't contain "HELLO, WORLD"
~~~

## Detached signature

This scenario is essentially the same as the previous ones, but uses a
detached signature.

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --userid Tomjon --export k.pgp
when I run sq sign --detached -o s.pgp --signer-key k.pgp hello.txt
when I run sq verify -o o.txt --signer-cert k.pgp --detached s.pgp hello.txt
~~~

We modify the original file so that the signature doesn't match.

~~~scenario
when I run sed -i 's/^hello, world/HELLO, WORLD/' hello.txt
when I try to run sq verify --signer-cert k.pgp --detached s.pgp hello.txt
then exit code is 1
then stdout doesn't contain "hello, world"
then stdout doesn't contain "HELLO, WORLD"
~~~

# ASCII Armor data representation: `sq armor`

The scenarios in this chapter verify that `sq` can convert data into
the "ASCII Armor" representation and back.

## Convert data file to armored format to stdout

_Requirement: We must be able to convert a file to armored format to
stdout._

~~~scenario
given an installed sq
given file hello.txt
when I run sq armor hello.txt
then stdout contains "-----BEGIN PGP ARMORED FILE-----"
then stdout contains "-----END PGP ARMORED FILE-----"
~~~

## Convert data file to armored format to file

_Requirement: We must be able to convert a file to armored format to a
named file._

~~~scenario
given an installed sq
given file hello.txt
given file hello.asc
when I run sq armor hello.txt -o hello.out
then files hello.asc and hello.out match
~~~


## Convert data file to armored format with desired label

_Requirement: We must be able to convert a file to armored format with
the label we choose._

~~~scenario
given an installed sq
given file hello.txt
when I run sq armor hello.txt --label auto
then stdout contains "-----BEGIN PGP ARMORED FILE-----"
when I run sq armor hello.txt --label message
then stdout contains "-----BEGIN PGP MESSAGE-----"
when I run sq armor hello.txt --label cert
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
when I run sq armor hello.txt --label key
then stdout contains "-----BEGIN PGP PRIVATE KEY BLOCK-----"
when I run sq armor hello.txt --label sig
then stdout contains "-----BEGIN PGP SIGNATURE-----"
when I run sq armor hello.txt --label file
then stdout contains "-----BEGIN PGP ARMORED FILE-----"
~~~

## Convert data file from armored format to stdout

_Requirement: We must be able to convert a file from armored format to
stdout._

~~~scenario
given an installed sq
given file hello.asc
when I run sq dearmor hello.asc
then stdout contains "hello, world"
~~~

## Convert data file from armored format to file

_Requirement: We must be able to convert a file from armored format to
a named file._

~~~scenario
given an installed sq
given file hello.txt
given file hello.asc
when I run sq dearmor hello.asc -o hello.out
then files hello.txt and hello.out match
~~~

## Armor round trip

_Requirement: We must be able to convert data to armored format and
back._

~~~scenario
given an installed sq
given file hello.txt
when I run sq armor hello.txt -o hello.tmp
when I run sq dearmor hello.tmp -o hello.out
then files hello.txt and hello.out match
~~~


# Test data file

We use this file as an input file in the tests. It is a very short
file, and a text file, but this is enough for the current set of
requirements and scenarios.

~~~{#hello.txt .file}
hello, world
~~~

This is the same content, but in ASCII armored representation.

~~~{#hello.asc .file}
-----BEGIN PGP ARMORED FILE-----

aGVsbG8sIHdvcmxkCg==
=FOuc
-----END PGP ARMORED FILE-----
~~~
