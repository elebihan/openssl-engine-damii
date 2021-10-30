# openssl-engine-damii

Example for an OpenSSL engine, where the keys are hard-coded. *THIS IS NOT FOR PRODUCTION*.

## Dependencies

- [Meson](http://mesonbuild.com/)
- [Ninja](https://ninja-build.org/) (version 1.7 or newer)

## Installation

To configure and build the project, execute:

```
mkdir build
meson . build
ninja -C build
```

To install the tools to system directories, execute:

```
ninja -C build install
```

To build and run test suite:

```sh
mkdir build
meson -Dtests=true build
ninja -C build test
```

## Usage

List capabilities and supported commands:

```sh
openssl engine -t -c -vv $PWD/build/src/damii.so
```

Encrypt file:

```sh
export OPENSSL_CONF=${prefix}/share/openssl-engine-damii/engine.conf
openssl enc -aes-256-cbc \
    -engine damii \
    -K $(printf "AES-KEY-01" | xxd -p) \
    -iv $(printf "AES-KEY-01" | xxd -p) \
    -in tests/data/test.plain.txt \
    -out test.enc.bin
```

Testing mTLS connection is done in two steps. First, start server:

```sh
cd tests/data
openssl s_server -CAfile ca.cert.pem \
    -key server.privkey.pem \
    -cert server.cert.pem \
    -state -verify 1 \
    -accept 5555
```

Then, assuming the installation directory is ``${prefix}``, start client:

```sh
cd tests/data
export OPENSSL_CONF=${prefix}/share/openssl-engine-damii/engine.conf
openssl s_client -CAfile ca.cert.pem \
    -engine damii -keyform engine -key "RSA-KEY-01" \
    -cert client.cert.pem \
    -connect localhost:5555
```

## License

This project is distributed under the terms of the MIT license.

See LICENSE-MIT for details.
