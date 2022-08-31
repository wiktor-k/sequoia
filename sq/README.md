# sq, the Sequoia-PGP command line tool

[Sequoia-PGP][] is an implementation of OpenPGP in Rust. It includes a
suite of library crates, which are meant to be used from applications.
This crate provides the `sq` command line application. `sq` is aimed
at command line users as a way to use OpenPGP conveniently from the
command line.

See the [sq user guide][] for instructions. The program also has built-in
help, using the `--help` option and `help` subcommand:

~~~sh
$ sq help
...
~~~

These are collected as the [sq help][] page, for your convenience.

## Generate manual pages

To generate manual pages, run:

~~~sh
SQ_MAN=xyzzy cargo run
~~~

This will generate manual pages in the `xyzzy` directory. The
directory will be created if it doesn't exist (but not any missing
parent directories). There will be one page for all of `sq`, and one
for each subcommand that doesn't have subcommands of its own.

[Sequoia-PGP]: https://sequoia-pgp.org/
[sq user guide]: https://sequoia-pgp.gitlab.io/sq-user-guide/
[sq help]: https://docs.sequoia-pgp.org/sq/index.html
