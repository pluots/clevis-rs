# clevis-rs

This crate is an implementation of the clevis client to the [Tang] protocol
used for generating encryption keys.

This crate is a work in progress.

## Tang

The basic operations path is taken from the [Tang] specification. In short, the
encrypting client must:

1. Request a public key with `GET /adv`. This returns a JWK set as a JWS
2. Verify the integrity of the received JWS using the included `verify` key

The config can specify:

- Tang URL
- Thumbprint

The URL specifies which server to query, while the thumbprint specifies a
preferred key.


## Licensing

Since this project takes heavy influence from the original [clevis], it retains
the GPLv3 license.

[tang]: https://github.com/latchset/tang
[clevis]: https://github.com/latchset/clevis
