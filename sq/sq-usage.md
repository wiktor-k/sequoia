A command-line frontend for Sequoia.

# Usage

```text
A command-line frontend for Sequoia, an implementation of OpenPGP

Functionality is grouped and available using subcommands.  Currently,
this interface is completely stateless.  Therefore, you need to supply
all configuration and certificates explicitly on each invocation.

OpenPGP data can be provided in binary or ASCII armored form.  This
will be handled automatically.  Emitted OpenPGP data is ASCII armored
by default.

We use the term "certificate", or cert for short, to refer to OpenPGP
keys that do not contain secrets.  Conversely, we use the term "key"
to refer to OpenPGP keys that do contain secrets.

USAGE:
    sq [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -f, --force
            Overwrites existing files

        --output-format <FORMAT>
            Produces output in FORMAT, if possible

            [env: SQ_OUTPUT_FORMAT=]
            [default: human-readable]
            [possible values: human-readable, json]

        --output-version <VERSION>
            Produces output variant VERSION

            [env: SQ_OUTPUT_VERSION=]

        --known-notation <NOTATION>
            Adds NOTATION to the list of known notations. This is used when
            validating signatures. Signatures that have unknown notations with
            the critical bit set are considered invalid.

    -h, --help
            Print help information

    -V, --version
            Print version information

SUBCOMMANDS:
    encrypt
            Encrypts a message
    decrypt
            Decrypts a message
    sign
            Signs messages or data files
    verify
            Verifies signed messages or detached signatures
    key
            Manages keys
    keyring
            Manages collections of keys or certs
    certify
            Certifies a User ID for a Certificate
    autocrypt
            Communicates certificates using Autocrypt
    keyserver
            Interacts with keyservers
    wkd
            Interacts with Web Key Directories
    armor
            Converts binary to ASCII
    dearmor
            Converts ASCII to binary
    inspect
            Inspects data, like file(1)
    packet
            Low-level packet manipulation
    revoke
            Generates revocation certificates
    help
            Print this message or the help of the given subcommand(s)
```

## Subcommand encrypt

```text
Encrypts a message

Encrypts a message for any number of recipients and with any number of
passwords, optionally signing the message in the process.

The converse operation is "sq decrypt".

USAGE:
    sq encrypt [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

        --compression <KIND>
            Selects compression scheme to use

            [default: pad]
            [possible values: none, pad, zip, zlib, bzip2]

    -h, --help
            Print help information

        --mode <MODE>
            Selects what kind of keys are considered for encryption.  Transport
            select subkeys marked as suitable for transport encryption, rest
            selects those for encrypting data at rest, and all selects all
            encryption-capable subkeys.

            [default: all]
            [possible values: transport, rest, all]

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

        --private-key-store <KEY_STORE>
            Provides parameters for private key store

        --recipient-cert <CERT-RING>
            Encrypts for all recipients in CERT-RING

    -s, --symmetric
            Adds a password to encrypt with.  The message can be decrypted with
            either one of the recipient's keys, or any password.

        --signer-key <KEY>
            Signs the message with KEY

    -t, --time <TIME>
            Chooses keys valid at the specified time and sets the signature's
            creation time

        --use-expired-subkey
            If a certificate has only expired encryption-capable subkeys, falls
            back to using the one that expired last

EXAMPLES:

# Encrypt a file using a certificate
$ sq encrypt --recipient-cert romeo.pgp message.txt

# Encrypt a file creating a signature in the process
$ sq encrypt --recipient-cert romeo.pgp --signer-key juliet.pgp message.txt

# Encrypt a file using a password
$ sq encrypt --symmetric message.txt
```

## Subcommand decrypt

```text
Decrypts a message

Decrypts a message using either supplied keys, or by prompting for a
password.  If message tampering is detected, an error is returned.
See below for details.

If certificates are supplied using the "--signer-cert" option, any
signatures that are found are checked using these certificates.
Verification is only successful if there is no bad signature, and the
number of successfully verified signatures reaches the threshold
configured with the "--signatures" parameter.

If the signature verification fails, or if message tampering is
detected, the program terminates with an exit status indicating
failure.  In addition to that, the last 25 MiB of the message are
withheld, i.e. if the message is smaller than 25 MiB, no output is
produced, and if it is larger, then the output will be truncated.

The converse operation is "sq encrypt".

USAGE:
    sq decrypt [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
        --dump
            Prints a packet dump to stderr

        --dump-session-key
            Prints the session key to stderr

    -h, --help
            Print help information

    -n, --signatures <N>
            Sets the threshold of valid signatures to N. The message will only
            be considered verified if this threshold is reached. [default: 1 if
            at least one signer cert file is given, 0 otherwise]

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

        --private-key-store <KEY_STORE>
            Provides parameters for private key store

        --recipient-key <KEY>
            Decrypts with KEY

        --session-key <SESSION-KEY>
            Decrypts an encrypted message using SESSION-KEY

        --signer-cert <CERT>
            Verifies signatures with CERT

    -x, --hex
            Prints a hexdump (implies --dump)

EXAMPLES:

# Decrypt a file using a secret key
$ sq decrypt --recipient-key juliet.pgp ciphertext.pgp

# Decrypt a file verifying signatures
$ sq decrypt --recipient-key juliet.pgp --signer-cert romeo.pgp ciphertext.pgp

# Decrypt a file using a password
$ sq decrypt ciphertext.pgp
```

## Subcommand sign

```text
Signs messages or data files

Creates signed messages or detached signatures.  Detached signatures
are often used to sign software packages.

The converse operation is "sq verify".

USAGE:
    sq sign [OPTIONS] [--] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -a, --append
            Appends a signature to existing signature

    -B, --binary
            Emits binary data

        --cleartext-signature
            Creates a cleartext signature

        --detached
            Creates a detached signature

    -h, --help
            Print help information

        --merge <SIGNED-MESSAGE>
            Merges signatures from the input and SIGNED-MESSAGE

    -n, --notarize
            Signs a message and all existing signatures

        --notation <NAME> <VALUE>
            Adds a notation to the certification.  A user-defined notation's
            name must be of the form "name@a.domain.you.control.org". If the
            notation's name starts with a !, then the notation is marked as
            being critical.  If a consumer of a signature doesn't understand a
            critical notation, then it will ignore the signature.  The notation
            is marked as being human readable.

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

        --private-key-store <KEY_STORE>
            Provides parameters for private key store

        --signer-key <KEY>
            Signs using KEY

    -t, --time <TIME>
            Chooses keys valid at the specified time and sets the signature's
            creation time

EXAMPLES:

# Create a signed message
$ sq sign --signer-key juliet.pgp message.txt

# Create a detached signature
$ sq sign --detached --signer-key juliet.pgp message.txt
```

## Subcommand verify

```text
Verifies signed messages or detached signatures

When verifying signed messages, the message is written to stdout or
the file given to --output.

When a detached message is verified, no output is produced.  Detached
signatures are often used to sign software packages.

Verification is only successful if there is no bad signature, and the
number of successfully verified signatures reaches the threshold
configured with the "--signatures" parameter.  If the verification
fails, the program terminates with an exit status indicating failure.
In addition to that, the last 25 MiB of the message are withheld,
i.e. if the message is smaller than 25 MiB, no output is produced, and
if it is larger, then the output will be truncated.

The converse operation is "sq sign".

USAGE:
    sq verify [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
        --detached <SIG>
            Verifies a detached signature

    -h, --help
            Print help information

    -n, --signatures <N>
            Sets the threshold of valid signatures to N. If this threshold is
            not reached, the message will not be considered verified.

            [default: 1]

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

        --signer-cert <CERT>
            Verifies signatures with CERT

EXAMPLES:

# Verify a signed message
$ sq verify --signer-cert juliet.pgp signed-message.pgp

# Verify a detached message
$ sq verify --signer-cert juliet.pgp --detached message.sig message.txt

SEE ALSO:

If you are looking for a standalone program to verify detached
signatures, consider using sequoia-sqv.
```

## Subcommand key

```text
Manages keys

We use the term "key" to refer to OpenPGP keys that do contain
secrets.  This subcommand provides primitives to generate and
otherwise manipulate keys.

Conversely, we use the term "certificate", or cert for short, to refer
to OpenPGP keys that do not contain secrets.  See "sq keyring" for
operations on certificates.

USAGE:
    sq key <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

SUBCOMMANDS:
    generate
            Generates a new key
    password
            Changes password protecting secrets
    userid
            Manages User IDs
    extract-cert
            Converts a key to a cert
    attest-certifications
            Attests to third-party certifications
    adopt
            Binds keys from one certificate to another
    help
            Print this message or the help of the given subcommand(s)
```

### Subcommand key generate

```text
Generates a new key

Generating a key is the prerequisite to receiving encrypted messages
and creating signatures.  There are a few parameters to this process,
but we provide reasonable defaults for most users.

When generating a key, we also generate a revocation certificate.
This can be used in case the key is superseded, lost, or compromised.
It is a good idea to keep a copy of this in a safe place.

After generating a key, use "sq key extract-cert" to get the
certificate corresponding to the key.  The key must be kept secure,
while the certificate should be handed out to correspondents, e.g. by
uploading it to a keyserver.

USAGE:
    sq key generate [OPTIONS]

OPTIONS:
    -c, --cipher-suite <CIPHER-SUITE>
            Selects the cryptographic algorithms for the key

            [default: cv25519]
            [possible values: rsa3k, rsa4k, cv25519]

        --can-authenticate
            Adds an authentication-capable subkey (default)

        --can-encrypt <PURPOSE>
            Adds an encryption-capable subkey. Encryption-capable subkeys can be
            marked as suitable for transport encryption, storage encryption, or
            both. [default: universal]

            [possible values: transport, storage, universal]

        --can-sign
            Adds a signing-capable subkey (default)

        --cannot-authenticate
            Adds no authentication-capable subkey

        --cannot-encrypt
            Adds no encryption-capable subkey

        --cannot-sign
            Adds no signing-capable subkey

        --creation-time <CREATION_TIME>
            Sets the key's creation time to TIME.  TIME is interpreted as an ISO
            8601
            timestamp.  To set the creation time to June 9, 2011 at midnight
            UTC,
            you can do:

            $ sq key generate --creation-time 20110609 --export noam.pgp

            To include a time, add a T, the time and optionally the timezone
            (the
            default timezone is UTC):

            $ sq key generate --creation-time 20110609T1938+0200 --export
            noam.pgp

    -e, --export <OUTFILE>
            Writes the key to OUTFILE

        --expires <TIME>
            Makes the key expire at TIME (as ISO 8601). Use "never" to create
            keys that do not expire.

        --expires-in <DURATION>
            Makes the key expire after DURATION. Either "N[ymwds]", for N years,
            months, weeks, days, seconds, or "never".

    -h, --help
            Print help information

        --rev-cert <FILE or ->
            Writes the revocation certificate to FILE. mandatory if OUTFILE is
            "-". [default: <OUTFILE>.rev]

    -u, --userid <EMAIL>
            Adds a userid to the key

        --with-password
            Protects the key with a password

EXAMPLES:

# First, this generates a key
$ sq key generate --userid "<juliet@example.org>" --export juliet.key.pgp

# Then, this extracts the certificate for distribution
$ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp

# Generates a key protecting it with a password
$ sq key generate --userid "<juliet@example.org>" --with-password

# Generates a key with multiple userids
$ sq key generate --userid "<juliet@example.org>" --userid "Juliet Capulet"
```

### Subcommand key password

```text
Changes password protecting secrets

Secret key material in keys can be protected by a password.  This
subcommand changes or clears this encryption password.

To emit the key with unencrypted secrets, either use `--clear` or
supply a zero-length password when prompted for the new password.

USAGE:
    sq key password [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

        --clear
            Emit a key with unencrypted secrets

    -h, --help
            Print help information

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

EXAMPLES:

# First, generate a key
$ sq key generate --userid "<juliet@example.org>" --export juliet.key.pgp

# Then, encrypt the secrets in the key with a password.
$ sq key password < juliet.key.pgp > juliet.encrypted_key.pgp

# And remove the password again.
$ sq key password --clear < juliet.encrypted_key.pgp > juliet.decrypted_key.pgp
```

### Subcommand key userid

```text
Manages User IDs

Add User IDs to, or strip User IDs from a key.

USAGE:
    sq key userid <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

SUBCOMMANDS:
    add
            Adds a User ID
    strip
            Strips a User ID
    help
            Print this message or the help of the given subcommand(s)
```

#### Subcommand key userid add

```text
Adds a User ID

A User ID can contain a name, like "Juliet" or an email address, like
"<juliet@example.org>".  Historically, a name and email address were often
combined as a single User ID, like "Juliet <juliet@example.org>".

USAGE:
    sq key userid add [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

        --creation-time <CREATION_TIME>
            Sets the creation time of this User ID's binding signature to TIME.
            TIME is interpreted as an ISO 8601 timestamp.  To set the creation
            time to June 28, 2022 at midnight UTC, you can do:

            $ sq key userid add --userid "Juliet" --creation-time 20210628 \
               juliet.key.pgp --output juliet-new.key.pgp

            To include a time, add a T, the time and optionally the timezone
            (the
            default timezone is UTC):

            $ sq key userid add --userid "Juliet" --creation-time
            20210628T1137+0200 \
               juliet.key.pgp --output juliet-new.key.pgp

    -h, --help
            Print help information

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

        --private-key-store <KEY_STORE>
            Provides parameters for private key store

    -u, --userid <USERID>
            User ID to add

EXAMPLES:

# First, this generates a key
$ sq key generate --userid "<juliet@example.org>" --export juliet.key.pgp

# Then, this adds a User ID
$ sq key userid add --userid "Juliet" juliet.key.pgp \
  --output juliet-new.key.pgp
```

#### Subcommand key userid strip

```text
Strips a User ID

Note that this operation does not reliably remove User IDs from a
certificate that has already been disseminated! (OpenPGP software
typically appends new information it receives about a certificate
to its local copy of that certificate.  Systems that have obtained
a copy of your certificate with the User ID that you are trying to
strip will not drop that User ID from their copy.)

In most cases, you will want to use the 'sq revoke userid' operation
instead.  That issues a revocation for a User ID, which can be used to mark
the User ID as invalidated.

However, this operation can be useful in very specific cases, in particular:
to remove a mistakenly added User ID before it has been uploaded to key
servers or otherwise shared.

Stripping a User ID may change how a certificate is interpreted.  This
is because information about the certificate like algorithm preferences,
the primary key's key flags, etc. is stored in the User ID's binding
signature.

USAGE:
    sq key userid strip [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

    -h, --help
            Print help information

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

    -u, --userid <USERID>
            The User IDs to strip.  Values must exactly match a User ID.

EXAMPLES:

# First, this generates a key
$ sq key generate --userid "<juliet@example.org>" --export juliet.key.pgp

# Then, this strips a User ID
$ sq key userid strip --userid "<juliet@example.org>" \
  --output juliet-new.key.pgp juliet.key.pgp
```

### Subcommand key extract-cert

```text
Converts a key to a cert

After generating a key, use this command to get the certificate
corresponding to the key.  The key must be kept secure, while the
certificate should be handed out to correspondents, e.g. by uploading
it to a keyserver.

USAGE:
    sq key extract-cert [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

    -h, --help
            Print help information

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

EXAMPLES:

# First, this generates a key
$ sq key generate --userid "<juliet@example.org>" --export juliet.key.pgp

# Then, this extracts the certificate for distribution
$ sq key extract-cert --output juliet.cert.pgp juliet.key.pgp
```

### Subcommand key attest-certifications

```text

Attests to third-party certifications allowing for their distribution

To prevent certificate flooding attacks, modern key servers prevent
uncontrolled distribution of third-party certifications on
certificates.  To make the key holder the sovereign over the
information over what information is distributed with the certificate,
the key holder needs to explicitly attest to third-party
certifications.

After the attestation has been created, the certificate has to be
distributed, e.g. by uploading it to a keyserver.

USAGE:
    sq key attest-certifications [OPTIONS] [KEY]

ARGS:
    <KEY>
            Changes attestations on KEY

OPTIONS:
        --all
            Attests to all certifications [default]

    -B, --binary
            Emits binary data

    -h, --help
            Print help information

        --none
            Removes all prior attestations

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

EXAMPLES:

# Attest to all certifications present on the key
$ sq key attest-certifications juliet.pgp

# Retract prior attestations on the key
$ sq key attest-certifications --none juliet.pgp
```

### Subcommand key adopt

```text
Binds keys from one certificate to another

This command allows one to transfer primary keys and subkeys into an
existing certificate.  Say you want to transition to a new
certificate, but have an authentication subkey on your current
certificate.  You want to keep the authentication subkey because it
allows access to SSH servers and updating their configuration is not
feasible.

USAGE:
    sq key adopt [OPTIONS] --key <KEY> [TARGET-KEY]

ARGS:
    <TARGET-KEY>
            Adds keys to TARGET-KEY

OPTIONS:
        --allow-broken-crypto
            Allows adopting keys from certificates using broken cryptography

    -B, --binary
            Emits binary data

    -h, --help
            Print help information

    -k, --key <KEY>
            Adds the key or subkey KEY to the TARGET-KEY

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

    -r, --keyring <KEY-RING>
            Supplies keys for use in --key.

EXAMPLES:

# Adopt an subkey into the new cert
$ sq key adopt --keyring juliet-old.pgp --key 0123456789ABCDEF -- juliet-new.pgp
```

## Subcommand keyring

```text
Manages collections of keys or certs

Collections of keys or certficicates (also known as "keyrings" when
they contain secret key material, and "certrings" when they don't) are
any number of concatenated certificates.  This subcommand provides
tools to list, split, join, merge, and filter keyrings.

Note: In the documentation of this subcommand, we sometimes use the
terms keys and certs interchangeably.

USAGE:
    sq keyring <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

SUBCOMMANDS:
    list
            Lists keys in a keyring
    split
            Splits a keyring into individual keys
    join
            Joins keys or keyrings into a single keyring
    merge
            Merges keys or keyrings into a single keyring
    filter
            Joins keys into a keyring applying a filter
    help
            Print this message or the help of the given subcommand(s)
```

### Subcommand keyring list

```text
Lists keys in a keyring

Prints the fingerprint as well as the primary userid for every
certificate encountered in the keyring.

USAGE:
    sq keyring list [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
        --all-userids
            Lists all user ids, even those that are expired, revoked, or not
            valid under the standard policy.

    -h, --help
            Print help information

EXAMPLES:

# List all certs
$ sq keyring list certs.pgp

# List all certs with a userid on example.org
$ sq keyring filter --domain example.org certs.pgp | sq keyring list
```

### Subcommand keyring split

```text
Splits a keyring into individual keys

Splitting up a keyring into individual keys helps with curating a
keyring.

The converse operation is "sq keyring join".

USAGE:
    sq keyring split [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

    -h, --help
            Print help information

    -p, --prefix <PREFIX>
            Writes to files with PREFIX [defaults: "FILE-" if FILE is set, or
            "output-" if read from stdin]

EXAMPLES:

# Split all certs
$ sq keyring split certs.pgp

# Split all certs, merging them first to avoid duplicates
$ sq keyring merge certs.pgp | sq keyring split
```

### Subcommand keyring join

```text
Joins keys or keyrings into a single keyring

Unlike "sq keyring merge", multiple versions of the same key are not
merged together.

The converse operation is "sq keyring split".

USAGE:
    sq keyring join [OPTIONS] [FILE]...

ARGS:
    <FILE>...
            Sets the input files to use

OPTIONS:
    -B, --binary
            Don't ASCII-armor the keyring

    -h, --help
            Print help information

    -o, --output <FILE>
            Sets the output file to use

EXAMPLES:

# Collect certs for an email conversation
$ sq keyring join juliet.pgp romeo.pgp alice.pgp
```

### Subcommand keyring merge

```text
Merges keys or keyrings into a single keyring

Unlike "sq keyring join", the certificates are buffered and multiple
versions of the same certificate are merged together.  Where data is
replaced (e.g., secret key material), data from the later certificate
is preferred.

USAGE:
    sq keyring merge [OPTIONS] [FILE]...

ARGS:
    <FILE>...
            Reads from FILE

OPTIONS:
    -B, --binary
            Emits binary data

    -h, --help
            Print help information

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

EXAMPLES:

# Merge certificate updates
$ sq keyring merge certs.pgp romeo-updates.pgp
```

### Subcommand keyring filter

```text
Joins keys into a keyring applying a filter

This can be used to filter keys based on given predicates,
e.g. whether they have a user id containing an email address with a
certain domain.  Additionally, the keys can be pruned to only include
components matching the predicates.

If no filters are supplied, everything matches.

If multiple predicates are given, they are or'ed, i.e. a key matches
if any of the predicates match.  To require all predicates to match,
chain multiple invocations of this command.  See EXAMPLES for
inspiration.

USAGE:
    sq keyring filter [OPTIONS] [FILE]...

ARGS:
    <FILE>...
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

        --domain <FQDN>
            Parses user ids into name and email address and case-sensitively
            matches on the domain of the email address, requiring an exact
            match.

        --email <ADDRESS>
            Parses user ids into name and email address and case-sensitively
            matches on the email address, requiring an exact match.

    -h, --help
            Print help information

        --handle <FINGERPRINT|KEYID>
            Matches on both primary keys and subkeys, including those
            certificates that match the given fingerprint or key id.

        --name <NAME>
            Parses user ids into name and email and case-sensitively matches on
            the name, requiring an exact match.

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

    -P, --prune-certs
            Removes certificate components not matching the filter

        --to-cert
            Converts any keys in the input to certificates.  Converting a key to
            a certificate removes secret key material from the key thereby
            turning it into a certificate.

        --userid <USERID>
            Case-sensitively matches on the user id, requiring an exact match.

EXAMPLES:

# Converts a key to a cert (i.e., remove any secret key material)
$ sq keyring filter --to-cert cat juliet.pgp

# Gets the keys with a user id on example.org
$ sq keyring filter --domain example.org keys.pgp

# Gets the keys with a user id on example.org or example.net
$ sq keyring filter --domain example.org --domain example.net keys.pgp

# Gets the keys with a user id with the name Juliet
$ sq keyring filter --name Juliet keys.pgp

# Gets the keys with a user id with the name Juliet on example.org
$ sq keyring filter --domain example.org keys.pgp | \
  sq keyring filter --name Juliet

# Gets the keys with a user id on example.org, pruning other userids
$ sq keyring filter --domain example.org --prune-certs certs.pgp
```

## Subcommand certify

```text
Certifies a User ID for a Certificate

Using a certification a keyholder may vouch for the fact that another
certificate legitimately belongs to a user id.  In the context of
emails this means that the same entity controls the key and the email
address.  These kind of certifications form the basis for the Web Of
Trust.

This command emits the certificate with the new certification.  The
updated certificate has to be distributed, preferably by sending it to
the certificate holder for attestation.  See also "sq key
attest-certification".

USAGE:
    sq certify [OPTIONS] <CERTIFIER-KEY> <CERTIFICATE> <USERID>

ARGS:
    <CERTIFIER-KEY>
            Creates the certification using CERTIFIER-KEY.

    <CERTIFICATE>
            Certifies CERTIFICATE.

    <USERID>
            Certifies USERID for CERTIFICATE.

OPTIONS:
    -a, --amount <TRUST_AMOUNT>
            Sets the amount of trust.  Values between 1 and 120 are meaningful.
            120 means fully trusted.  Values less than 120 indicate the degree
            of trust.  60 is usually used for partially trusted.

            [default: 120]

        --allow-not-alive-certifier
            Allows the key to make a certification even if the current time is
            prior to its creation time or the current time is at or after its
            expiration time.

        --allow-revoked-certifier
            Don't fail if the certificate making the certification is revoked.

    -B, --binary
            Emits binary data

    -d, --depth <TRUST_DEPTH>
            Sets the trust depth (sometimes referred to as the trust level).  0
            means a normal certification of <CERTIFICATE, USERID>.  1 means
            CERTIFICATE is also a trusted introducer, 2 means CERTIFICATE is a
            meta-trusted introducer, etc.

            [default: 0]

        --expires <TIME>
            Makes the certification expire at TIME (as ISO 8601). Use "never" to
            create certifications that do not expire.

        --expires-in <DURATION>
            Makes the certification expire after DURATION. Either "N[ymwds]",
            for N years, months, weeks, days, seconds, or "never".  [default:
            5y]

    -h, --help
            Print help information

    -l, --local
            Makes the certification a local certification.  Normally, local
            certifications are not exported.

        --non-revocable
            Marks the certification as being non-revocable. That is, you cannot
            later revoke this certification.  This should normally only be used
            with an expiration.

        --notation <NAME> <VALUE>
            Adds a notation to the certification.  A user-defined notation's
            name must be of the form "name@a.domain.you.control.org". If the
            notation's name starts with a !, then the notation is marked as
            being critical.  If a consumer of a signature doesn't understand a
            critical notation, then it will ignore the signature.  The notation
            is marked as being human readable.

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

        --private-key-store <KEY_STORE>
            Provides parameters for private key store

    -r, --regex <REGEX>
            Adds a regular expression to constrain what a trusted introducer can
            certify.  The regular expression must match the certified User ID in
            all intermediate introducers, and the certified certificate.
            Multiple regular expressions may be specified.  In that case, at
            least one must match.

        --time <TIME>
            Sets the certification time to TIME.  TIME is interpreted as an ISO
            8601
            timestamp.  To set the certification time to June 9, 2011 at
            midnight UTC,
            you can do:

            $ sq certify --time 20130721 neal.pgp ada.pgp ada

            To include a time, add a T, the time and optionally the timezone
            (the
            default timezone is UTC):

            $ sq certify --time 20130721T0550+0200 neal.pgp ada.pgp ada

EXAMPLES:

# Juliet certifies that Romeo controls romeo.pgp and romeo@example.org
$ sq certify juliet.pgp romeo.pgp "<romeo@example.org>"
```

## Subcommand autocrypt

```text
Communicates certificates using Autocrypt

Autocrypt is a standard for mail user agents to provide convenient
end-to-end encryption of emails.  This subcommand provides a limited
way to produce and consume headers that are used by Autocrypt to
communicate certificates between clients.

See https://autocrypt.org/

USAGE:
    sq autocrypt <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

SUBCOMMANDS:
    decode
            Reads Autocrypt-encoded certificates
    encode-sender
            Encodes a certificate into an Autocrypt header
    help
            Print this message or the help of the given subcommand(s)
```

### Subcommand autocrypt decode

```text
Reads Autocrypt-encoded certificates

Given an autocrypt header (or an key-gossip header), this command
extracts the certificate encoded within it.

The converse operation is "sq autocrypt encode-sender".

USAGE:
    sq autocrypt decode [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

    -h, --help
            Print help information

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

EXAMPLES:

# Extract all certificates from a mail
$ sq autocrypt decode autocrypt.eml
```

### Subcommand autocrypt encode-sender

```text
Encodes a certificate into an Autocrypt header

A certificate can be encoded and included in a header of an email
message.  This command encodes the certificate, adds the senders email
address (which must match the one used in the "From" header), and the
senders "prefer-encrypt" state (see the Autocrypt spec for more
information).

The converse operation is "sq autocrypt decode".

USAGE:
    sq autocrypt encode-sender [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
        --email <ADDRESS>
            Sets the address [default: primary userid]

    -h, --help
            Print help information

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

        --prefer-encrypt <PREFER-ENCRYPT>
            Sets the prefer-encrypt attribute

            [default: nopreference]
            [possible values: nopreference, mutual]

EXAMPLES:

# Encodes a certificate
$ sq autocrypt encode-sender juliet.pgp

# Encodes a certificate with an explicit sender address
$ sq autocrypt encode-sender --email juliet@example.org juliet.pgp

# Encodes a certificate while indicating the willingness to encrypt
$ sq autocrypt encode-sender --prefer-encrypt mutual juliet.pgp
```

## Subcommand keyserver

```text
Interacts with keyservers

USAGE:
    sq keyserver [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

    -p, --policy <NETWORK-POLICY>
            Sets the network policy to use [default: encrypted] [possible
            values: offline, anonymized, encrypted, insecure]

    -s, --server <URI>
            Sets the keyserver to use

SUBCOMMANDS:
    get     Retrieves a key
    help    Print this message or the help of the given subcommand(s)
    send    Sends a key
```

### Subcommand keyserver get

```text
Retrieves a key

USAGE:
    sq keyserver get [OPTIONS] <QUERY>

ARGS:
    <QUERY>    Retrieve certificate(s) using QUERY. This may be a
               fingerprint, a KeyID, or an email address.

OPTIONS:
    -B, --binary           Emits binary data
    -h, --help             Print help information
    -o, --output <FILE>    Writes to FILE or stdout if omitted
```

### Subcommand keyserver send

```text
Sends a key

USAGE:
    sq keyserver send [FILE]

ARGS:
    <FILE>    Reads from FILE or stdin if omitted

OPTIONS:
    -h, --help    Print help information
```

## Subcommand wkd

```text
Interacts with Web Key Directories

USAGE:
    sq wkd [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -n, --network-policy <NETWORK-POLICY>
            Sets the network policy to use [default: encrypted] [possible
            values: offline, anonymized, encrypted, insecure]

    -h, --help
            Print help information

SUBCOMMANDS:
    generate      Generates a Web Key Directory for the given domain and
                      keys.
    get           Queries for certs using Web Key Directory
    direct-url    Prints the direct Web Key Directory URL of an email
                      address.
    url           Prints the advanced Web Key Directory URL of an email
                      address.
    help          Print this message or the help of the given subcommand(s)
```

### Subcommand wkd generate

```text
Generates a Web Key Directory for the given domain and keys.  If the WKD exists,
the new keys will be inserted and it is updated and existing ones will be
updated.



        A WKD is per domain, and can be queried using the advanced or the direct
method. The advanced method uses a URL with a subdomain 'openpgpkey'. As per the
specification, the advanced method is to be preferred. The direct method may
only be used if the subdomain doesn't exist. The advanced method allows web key
directories for several domains on one web server.



        The contents of the generated WKD must be copied to a web server so that
they are accessible under https://openpgpkey.example.com/.well-known/openpgp/...
for the advanced version, and https://example.com/.well-known/openpgp/... for
the direct version. sq does not copy files to the web server.

USAGE:
    sq wkd generate [OPTIONS] <WEB-ROOT> <FQDN> [CERT-RING]

ARGS:
    <WEB-ROOT>
            Writes the WKD to WEB-ROOT. Transfer this directory to the
            webserver.

    <FQDN>
            Generates a WKD for a fully qualified domain name for email

    <CERT-RING>
            Adds certificates from CERT-RING to the WKD

OPTIONS:
    -d, --direct-method
            Uses the direct method [default: advanced method]

    -h, --help
            Print help information

    -s, --skip
            Skips certificates that do not have User IDs for given domain.

EXAMPLES:

# Generate a WKD in /tmp/wkdroot from certs.pgp for example.com.
$ sq wkd generate /tmp/wkdroot example.com certs.ppg
```

### Subcommand wkd get

```text
Queries for certs using Web Key Directory

USAGE:
    sq wkd get [OPTIONS] <ADDRESS>

ARGS:
    <ADDRESS>    Queries a cert for ADDRESS

OPTIONS:
    -B, --binary           Emits binary data
    -h, --help             Print help information
    -o, --output <FILE>    Writes to FILE or stdout if omitted
```

### Subcommand wkd direct-url

```text
Prints the direct Web Key Directory URL of an email address.

USAGE:
    sq wkd direct-url <ADDRESS>

ARGS:
    <ADDRESS>    Queries for ADDRESS

OPTIONS:
    -h, --help    Print help information
```

### Subcommand wkd url

```text
Prints the advanced Web Key Directory URL of an email address.

USAGE:
    sq wkd url <ADDRESS>

ARGS:
    <ADDRESS>    Queries for ADDRESS

OPTIONS:
    -h, --help    Print help information
```

## Subcommand armor

```text
Converts binary to ASCII

To make encrypted data easier to handle and transport, OpenPGP data
can be transformed to an ASCII representation called ASCII Armor.  sq
emits armored data by default, but this subcommand can be used to
convert existing OpenPGP data to its ASCII-encoded representation.

The converse operation is "sq dearmor".

USAGE:
    sq armor [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -h, --help
            Print help information

        --label <LABEL>
            Selects the kind of armor header

            [default: auto]
            [possible values: auto, message, cert, key, sig, file]

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

EXAMPLES:

# Convert a binary certificate to ASCII
$ sq armor binary-juliet.pgp

# Convert a binary message to ASCII
$ sq armor binary-message.pgp
```

## Subcommand dearmor

```text
Converts ASCII to binary

To make encrypted data easier to handle and transport, OpenPGP data
can be transformed to an ASCII representation called ASCII Armor.  sq
transparently handles armored data, but this subcommand can be used to
explicitly convert existing ASCII-encoded OpenPGP data to its binary
representation.

The converse operation is "sq armor".

USAGE:
    sq dearmor [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -h, --help
            Print help information

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

EXAMPLES:

# Convert a ASCII certificate to binary
$ sq dearmor ascii-juliet.pgp

# Convert a ASCII message to binary
$ sq dearmor ascii-message.pgp
```

## Subcommand inspect

```text
Inspects data, like file(1)

It is often difficult to tell from cursory inspection using cat(1) or
file(1) what kind of OpenPGP one is looking at.  This subcommand
inspects the data and provides a meaningful human-readable description
of it.

USAGE:
    sq inspect [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
        --certifications
            Prints third-party certifications

    -h, --help
            Print help information

EXAMPLES:

# Inspects a certificate
$ sq inspect juliet.pgp

# Inspects a certificate ring
$ sq inspect certs.pgp

# Inspects a message
$ sq inspect message.pgp

# Inspects a detached signature
$ sq inspect message.sig
```

## Subcommand packet

```text
Low-level packet manipulation

An OpenPGP data stream consists of packets.  These tools allow working
with packet streams.  They are mostly of interest to developers, but
"sq packet dump" may be helpful to a wider audience both to provide
valuable information in bug reports to OpenPGP-related software, and
as a learning tool.

USAGE:
    sq packet <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

SUBCOMMANDS:
    dump
            Lists packets
    decrypt
            Unwraps an encryption container
    split
            Splits a message into packets
    join
            Joins packets split across files
    help
            Print this message or the help of the given subcommand(s)
```

### Subcommand packet dump

```text

Lists packets

Creates a human-readable description of the packet sequence.
Additionally, it can print cryptographic artifacts, and print the raw
octet stream similar to hexdump(1), annotating specifically which
bytes are parsed into OpenPGP values.

To inspect encrypted messages, either supply the session key, or see
"sq decrypt --dump" or "sq packet decrypt".

USAGE:
    sq packet dump [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -h, --help
            Print help information

        --mpis
            Prints cryptographic artifacts

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

        --session-key <SESSION-KEY>
            Decrypts an encrypted message using SESSION-KEY

    -x, --hex
            Prints a hexdump

EXAMPLES:

# Prints the packets of a certificate
$ sq packet dump juliet.pgp

# Prints cryptographic artifacts of a certificate
$ sq packet dump --mpis juliet.pgp

# Prints a hexdump of a certificate
$ sq packet dump --hex juliet.pgp

# Prints the packets of an encrypted message
$ sq packet dump --session-key AAAABBBBCCCC... ciphertext.pgp
```

### Subcommand packet decrypt

```text
Unwraps an encryption container

Decrypts a message, dumping the content of the encryption container
without further processing.  The result is a valid OpenPGP message
that can, among other things, be inspected using "sq packet dump".

USAGE:
    sq packet decrypt [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

        --dump-session-key
            Prints the session key to stderr

    -h, --help
            Print help information

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

        --private-key-store <KEY_STORE>
            Provides parameters for private key store

        --recipient-key <KEY>
            Decrypts the message with KEY

        --session-key <SESSION-KEY>
            Decrypts an encrypted message using SESSION-KEY

EXAMPLES:

# Unwraps the encryption revealing the signed message
$ sq packet decrypt --recipient-key juliet.pgp ciphertext.pgp
```

### Subcommand packet split

```text
Splits a message into packets

Splitting a packet sequence into individual packets, then recombining
them freely with "sq packet join" is a great way to experiment with
OpenPGP data.

The converse operation is "sq packet join".

USAGE:
    sq packet split [OPTIONS] [FILE]

ARGS:
    <FILE>
            Reads from FILE or stdin if omitted

OPTIONS:
    -h, --help
            Print help information

    -p, --prefix <PREFIX>
            Writes to files with PREFIX [defaults: "FILE-" if FILE is set, or
            "output-" if read from stdin]

EXAMPLES:

# Split a certificate into individual packets
$ sq packet split juliet.pgp
```

### Subcommand packet join

```text
Joins packets split across files

Splitting a packet sequence into individual packets, then recombining
them freely with "sq packet join" is a great way to experiment with
OpenPGP data.

The converse operation is "sq packet split".

USAGE:
    sq packet join [OPTIONS] [FILE]...

ARGS:
    <FILE>...
            Reads from FILE or stdin if omitted

OPTIONS:
    -B, --binary
            Emits binary data

    -h, --help
            Print help information

        --label <LABEL>
            Selects the kind of armor header

            [default: auto]
            [possible values: auto, message, cert, key, sig, file]

    -o, --output <FILE>
            Writes to FILE or stdout if omitted

EXAMPLES:

# Split a certificate into individual packets
$ sq packet split juliet.pgp

# Then join only a subset of these packets
$ sq packet join juliet.pgp-[0-3]*
```

## Subcommand revoke

```text
Generates revocation certificates.

A revocation certificate indicates that a certificate, a subkey, a
User ID, or a signature should not be used anymore.

A revocation certificate includes two fields, a type and a
human-readable explanation, which allows the issuer to indicate why
the revocation certificate was issued.  It is important to set the
type field accurately as this allows an OpenPGP implementation to
better reason about artifacts whose validity relies on the revoked
object.  For instance, if a certificate is retired, it is reasonable
to consider signatures that it made prior to its retirement as still
being valid.  However, if a certificate's secret key material is
compromised, any signatures that it made should be considered
potentially forged, as they could have been made by an attacker and
backdated.

As the intent of a revocation certificate is to stop others from using
a certificate, it is necessary to distribute the revocation
certificate.  One effective way to do this is to upload the revocation
certificate to a keyserver.

USAGE:
    sq revoke <SUBCOMMAND>

OPTIONS:
    -h, --help
            Print help information

SUBCOMMANDS:
    certificate
            Revoke a certificate
    subkey
            Revoke a subkey
    userid
            Revoke a User ID
    help
            Print this message or the help of the given subcommand(s)

EXAMPLES:

# Revoke a certificate.
$ sq revoke certificate --time 20220101 --certificate juliet.pgp \
  compromised "My parents went through my things, and found my backup."

# Revoke a User ID.
$ sq revoke userid --time 20220101 --certificate juliet.pgp \
  "Juliet <juliet@capuleti.it>" retired "I've left the family."
```

### Subcommand revoke certificate

```text
Revokes a certificate

Creates a revocation certificate for the certificate.

If "--revocation-key" is provided, then that key is used to create
the signature.  If that key is different from the certificate being
revoked, this creates a third-party revocation.  This is normally only
useful if the owner of the certificate designated the key to be a
designated revoker.

If "--revocation-key" is not provided, then the certificate must
include a certification-capable key.

USAGE:
    sq revoke certificate [OPTIONS] <REASON> <MESSAGE>

ARGS:
    <REASON>
            The reason for the revocation.  This must be either: compromised,
            superseded, retired, or unspecified:

              - compromised means that the secret key material may have been
                compromised.  Prefer this value if you suspect that the secret
                key has been leaked.

              - superseded means that the owner of the certificate has replaced
                it with a new certificate.  Prefer "compromised" if the secret
                key material has been compromised even if the certificate is
            also
                being replaced!  You should include the fingerprint of the new
                certificate in the message.

              - retired means that this certificate should not be used anymore,
                and there is no replacement.  This is appropriate when someone
                leaves an organisation.  Prefer "compromised" if the secret key
                material has been compromised even if the certificate is also
                being retired!  You should include how to contact the owner, or
                who to contact instead in the message.

              - unspecified means that none of the three other three reasons
                apply.  OpenPGP implementations conservatively treat this type
                of revocation similar to a compromised key.

            If the reason happened in the past, you should specify that using
            the
            --time argument.  This allows OpenPGP implementations to more
            accurately reason about objects whose validity depends on the
            validity
            of the certificate.

            [possible values: compromised, superseded, retired, unspecified]

    <MESSAGE>
            A short, explanatory text that is shown to a viewer of the
            revocation certificate.  It explains why the certificate has been
            revoked.  For instance, if Alice has created a new key, she would
            generate a 'superseded' revocation certificate for her old key, and
            might include the message "I've created a new certificate,
            FINGERPRINT, please use that in the future."

OPTIONS:
    -B, --binary
            Emits binary data

        --certificate <FILE>
            Reads the certificate to revoke from FILE or stdin, if omitted.  It
            is an error for the file to contain more than one certificate.

    -h, --help
            Print help information

        --notation <NAME> <VALUE>
            Adds a notation to the certification.  A user-defined notation's
            name must be of the form "name@a.domain.you.control.org". If the
            notation's name starts with a !, then the notation is marked as
            being critical.  If a consumer of a signature doesn't understand a
            critical notation, then it will ignore the signature.  The notation
            is marked as being human readable.

        --private-key-store <KEY_STORE>
            Provides parameters for private key store

        --revocation-key <KEY>
            Signs the revocation certificate using KEY.  If the key is different
            from the certificate, this creates a third-party revocation.  If
            this option is not provided, and the certificate includes secret key
            material, then that key is used to sign the revocation certificate.

    -t, --time <TIME>
            Chooses keys valid at the specified time and sets the revocation
            certificate's creation time
```

### Subcommand revoke subkey

```text
Revokes a subkey

Creates a revocation certificate for a subkey.

If "--revocation-key" is provided, then that key is used to create the
signature.  If that key is different from the certificate being revoked, this
creates a third-party revocation.  This is normally only useful if the owner of
the certificate designated the key to be a designated revoker.

If "--revocation-key" is not provided, then the certificate must include a
certification-capable key.

USAGE:
    sq revoke subkey [OPTIONS] <SUBKEY> <REASON> <MESSAGE>

ARGS:
    <SUBKEY>
            The subkey to revoke.  This must either be the subkey's Key ID or
            its fingerprint.

    <REASON>
            The reason for the revocation.  This must be either: compromised,
            superseded, retired, or unspecified:

              - compromised means that the secret key material may have been
                compromised.  Prefer this value if you suspect that the secret
                key has been leaked.

              - superseded means that the owner of the certificate has replaced
                it with a new certificate.  Prefer "compromised" if the secret
                key material has been compromised even if the certificate is
                also being replaced!  You should include the fingerprint of the
                new certificate in the message.

              - retired means that this certificate should not be used anymore,
                and there is no replacement.  This is appropriate when someone
                leaves an organisation.  Prefer "compromised" if the secret key
                material has been compromised even if the certificate is also
                being retired!  You should include how to contact the owner, or
                who to contact instead in the message.

              - unspecified means that none of the three other three reasons
                apply.  OpenPGP implementations conservatively treat this type
                of revocation similar to a compromised key.

            If the reason happened in the past, you should specify that using
            the --time argument.  This allows OpenPGP implementations to more
            accurately reason about objects whose validity depends on the
            validity of the certificate.

            [possible values: compromised, superseded, retired, unspecified]

    <MESSAGE>
            A short, explanatory text that is shown to a viewer of the
            revocation certificate.  It explains why the subkey has been
            revoked.  For instance, if Alice has created a new key, she would
            generate a 'superseded' revocation certificate for her old key, and
            might include the message "I've created a new subkey, please refresh
            the certificate.

OPTIONS:
    -B, --binary
            Emits binary data

        --certificate <FILE>
            Reads the certificate containing the subkey to revoke from FILE or
            stdin, if omitted.  It is an error for the file to contain more than
            one certificate.

    -h, --help
            Print help information

        --notation <NAME> <VALUE>
            Adds a notation to the certification.  A user-defined notation's
            name must be of the form "name@a.domain.you.control.org". If the
            notation's name starts with a !, then the notation is marked as
            being critical.  If a consumer of a signature doesn't understand a
            critical notation, then it will ignore the signature.  The notation
            is marked as being human readable.

        --private-key-store <KEY_STORE>
            Provides parameters for private key store

        --revocation-key <KEY>
            Signs the revocation certificate using KEY.  If the key is different
            from the certificate, this creates a third-party revocation.  If
            this option is not provided, and the certificate includes secret key
            material, then that key is used to sign the revocation certificate.

    -t, --time <TIME>
            Chooses keys valid at the specified time and sets the revocation
            certificate's creation time
```

### Subcommand revoke userid

```text
Revokes a User ID

Creates a revocation certificate for a User ID.

If "--revocation-key" is provided, then that key is used to create the
signature.  If that key is different from the certificate being revoked, this
creates a third-party revocation.  This is normally only useful if the owner of
the certificate designated the key to be a designated revoker.

If "--revocation-key" is not provided, then the certificate must include a
certification-capable key.

USAGE:
    sq revoke userid [OPTIONS] <USERID> <REASON> <MESSAGE>

ARGS:
    <USERID>
            The User ID to revoke.  By default, this must exactly match a
            self-signed User ID.  Use --force to generate a revocation
            certificate for a User ID, which is not self signed.

    <REASON>
            The reason for the revocation.  This must be either: retired, or
            unspecified:

              - retired means that this User ID is no longer valid.  This is
                appropriate when someone leaves an organisation, and the
                organisation does not have their secret key material.  For
                instance, if someone was part of Debian and retires, they would
                use this to indicate that a Debian-specific User ID is no longer
                valid.

              - unspecified means that a different reason applies.

            If the reason happened in the past, you should specify that using
            the --time argument.  This allows OpenPGP implementations to more
            accurately reason about objects whose validity depends on the
            validity of a User ID.

            [possible values: retired, unspecified]

    <MESSAGE>
            A short, explanatory text that is shown to a viewer of the
            revocation certificate.  It explains why the certificate has been
            revoked.  For instance, if Alice has created a new key, she would
            generate a 'superseded' revocation certificate for her old key, and
            might include the message "I've created a new certificate,
            FINGERPRINT, please use that in the future."

OPTIONS:
    -B, --binary
            Emits binary data

        --certificate <FILE>
            Reads the certificate to revoke from FILE or stdin, if omitted.  It
            is an error for the file to contain more than one certificate.

    -h, --help
            Print help information

        --notation <NAME> <VALUE>
            Adds a notation to the certification.  A user-defined notation's
            name must be of the form "name@a.domain.you.control.org". If the
            notation's name starts with a !, then the notation is marked as
            being critical.  If a consumer of a signature doesn't understand a
            critical notation, then it will ignore the signature.  The notation
            is marked as being human readable.

        --private-key-store <KEY_STORE>
            Provides parameters for private key store

        --revocation-key <KEY>
            Signs the revocation certificate using KEY.  If the key is different
            from the certificate, this creates a third-party revocation.  If
            this option is not provided, and the certificate includes secret key
            material, then that key is used to sign the revocation certificate.

    -t, --time <TIME>
            Chooses keys valid at the specified time and sets the revocation
            certificate's creation time
```

### Subcommand revoke EXAMPLES:

```text

USAGE:
    sq revoke <SUBCOMMAND>

For more information try --help
```

### Subcommand revoke #

```text

USAGE:
    sq revoke <SUBCOMMAND>

For more information try --help
```

### Subcommand revoke compromised

```text

USAGE:
    sq revoke <SUBCOMMAND>

For more information try --help
```

### Subcommand revoke #

```text

USAGE:
    sq revoke <SUBCOMMAND>

For more information try --help
```

### Subcommand revoke "Juliet

```text

USAGE:
    sq revoke <SUBCOMMAND>

For more information try --help
```
