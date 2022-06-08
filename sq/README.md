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

[Sequoia-PGP]: https://sequoia-pgp.org/
[sq user guide]: https://sequoia-pgp.gitlab.io/sq-user-guide/
[sq help]: https://docs.sequoia-pgp.org/sq/index.html
