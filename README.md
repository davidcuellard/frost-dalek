# FROST [![](https://img.shields.io/crates/v/frost-dalek.svg)](https://crates.io/crates/frost-dalek) [![](https://docs.rs/frost-dalek/badge.svg)](https://docs.rs/frost-dalek) [![](https://travis-ci.com/github/isislovecruft/frost-dalek.svg?branch=master)](https://travis-ci.org/isislovecruft/frost-dalek)

FROST-dalek is a Rust implementation of the
[FROST: Flexible Round-Optimised Schnorr Threshold signatures](https://eprint.iacr.org/2020/852) protocol, designed for efficient and secure threshold signature generation by Chelsea Komlo and Ian Goldberg.

Threshold signatures allow a group of signers to collaboratively produce a signature without requiring all participants to be present. This is ideal for applications that require resilience and decentralization, such as cryptocurrency wallets, multi-party computation, and distributed systems.

### Key Features:

- Efficient threshold Schnorr signature scheme.
- Flexible t-of-n threshold cryptography support.
- Works in both distributed and centralized setups for demonstration purposes.
- Built with security, performance, and ease of integration in mind.

## Use cases

The use cases for FROST (Flexible Round-Optimised Schnorr Threshold signatures) include:

- **Distributed Key Management**: Securely managing cryptographic keys across multiple parties without a single point of failure.
- **Multi-Signature Wallets**: Enabling multiple parties to jointly control a cryptocurrency wallet, requiring a subset of them to sign transactions.
- **Secure Voting Systems**: Ensuring that votes are securely cast and tallied in a decentralized manner.
- **Collaborative Signing**: Allowing multiple entities to collaboratively sign documents or transactions, ensuring that a threshold number of participants agree.
- **Threshold Encryption**: Encrypting data such that it can only be decrypted if a threshold number of parties cooperate.

## Features

- **Threshold Signatures**: Supports flexible threshold configurations.
- **Round-Optimised**: Minimizes the number of communication rounds required.
- **Ristretto Group**: Utilizes the Ristretto group for secure and efficient cryptographic operations.
- **`no_std` Support**: Most of the crate is `no_std` compliant, with the exception of signature creation and aggregation which require the standard library.

## Documentation

Please see here [the full documentation](https://docs.rs/frost-dalek).

### Example

Run the example program provided with the library to explore its API:

```bash
cargo run --example frost_api_example
```

Here’s a quick overview of the FROST signing process:

1. Key Generation: Generate a public group key and n private key shares for participants, requiring a threshold t of participants to sign.

2. Signing: Use at least t participant shares to collaboratively create a valid signature for a message.

3. Verification: Verify the produced signature using the group public key.

## Installation
To include FROST-dalek in your Rust project, add it as a dependency in your Cargo.toml:

```toml
[dependencies]
frost-dalek = "0.2.3"
```

## Note on `no_std` usage

Most of this crate is `no_std` compliant, however, the current
implementation uses `HashMap`s for the signature creation and aggregation
protocols, and thus requires the standard library.

## WARNING

This code is likely not stable. The author is working with the paper authors on
an RFC which, if/when adopted, will allow us to stabilise this codebase. Until
then, the structure and construction of these signatures, as well as wireformats
for several types which must be sent between signing parties, may change in
incompatible ways.
