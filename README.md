# clevis-rs

This crate is an implementation of the clevis client to the [Tang] protocol
used for generating encryption keys.

This project is NOT officially associated with Latchset, publisher of Clevis
and Tang.

This crate is a work in progress.

See the documentation for further information: <https://docs.rs/clevis>.

## Tang Setup

You need a tang server running in order to use this crate. The
[padhihomelab/tang](https://hub.docker.com/r/padhihomelab/tang) image is the
easiest way to get started with this.

```sh
docker run --rm -d \
    -v $(pwd)/tang-db:/db \
    -e ENABLE_IPv6=1 \
    -p 11697:8080 \
    --name tang-backend \
    padhihomelab/tang
```

This will store the Tang keys in the directory at `./tang-db`, adjust this as
needed.

Any port can be selected (this crate uses `11697` for examples since it is the
ASCII of `ta` (as in `tang`), so easy to remember).

## Licensing

Since this project takes heavy influence from the original [clevis], it retains
the GPLv3 license.

[tang]: https://github.com/latchset/tang
[clevis]: https://github.com/latchset/clevis
