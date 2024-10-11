# Cli tools for Aleo setup 1

Some handy utilities for testing purposes

## Build Guide

Use stable Rust to build (at the moment of writing 1.54)

```bash
cargo build --release
```

Alternatively, to add the binaries to the PATH run:

```bash
cargo install --path .
```

This will add the `public-key-extractor` and `view-key` binaries to `.cargo/bin` folder

## Usage

```bash
# To generate a view key:
view-key > view_key.txt

# To produce a public key out of a private key:
public-key-extractor --path keys.json
```

## Encrypt and Decrypt Guide

Encrypt text:

```bash
cargo run --bin encrypt_text -- --address aleo1ekhu99p7m6e8slh5tpjay28vv3jklmxhtrmphg43t7hvva7hyqgqtkq846 --plaintext "foo"
```

Decrypt text (using `keys.json`):

```bash
cargo run --bin decrypt_text -- --path ./keys.json --ciphertext d62da3d3e9732ef58d98a7a1c987aa7fff8046451f4cdcf552b659171d7120057bf9c5485fcd77c5e3f6c56ed2b6d6df487e327c4de04b5ffe7e6d98761ac00a
```
