# uni_vault

## Overview

uni_vault is a high-level Rust crate that provides secure vault functionality using advanced encryption techniques. It leverages Trezor Ethereum signatures as a seed to generate SSH private keys and Rage key pairs, ensuring robust asymmetric encryption and decryption operations. Built on top of the signature_to_keys crate, uni_vault abstracts complex cryptographic processes into an accessible API for secure data storage and management.

---

## Features

- High-level abstraction over complex cryptographic operations.
- Secure encryption and decryption using the Rage encryption scheme.
- Integration with hardware wallets (e.g., Trezor) for enhanced security.
- Configurable via a builder pattern.
- Utilizes signature_to_keys for advanced key derivation and SSH key generation.
- Supports customizable settings such as BIP32 derivation paths and recipient management.

---

## Installation

Add uni_vault to your Cargo.toml file:

```shell
cargo add uni_vault
```

---

## Usage

Below is an example demonstrating how to use uni_vault for encryption and decryption:

```rust
use uni_vault::encryptor::{
    asymmetric::rage_trezor::{RageTrezorEncryptorBuilder, RageTrezorEncryptor},
    Encryptor,
    HasUserIdentifier,
    SecretType,
};
use uni_vault::common::traits::JsonSerializable;

let password = b"my_secret_password";
let mut encryptor: RageTrezorEncryptor = RageTrezorEncryptorBuilder::default()
    .platform_id("example.com")
    .username("user123")
    .secret_type(SecretType::Password)
    .bip32_path("m/44h/60h/11h/0/12")
    .comment("Example encryption using uni_vault")
    .build()
    .unwrap();

// Encrypt the secret.
let encrypted = encryptor.encrypt(password).unwrap();

// Decrypt the secret.
let decrypted = encryptor.decrypt(&encrypted).unwrap();

assert_eq!(password.to_vec(), decrypted);
```

---

## API Reference

For detailed API documentation, please refer to the [docs.rs page for uni_vault](https://docs.rs/uni_vault).

---

## Contributing

Contributions are welcome!


---

## License

This project is licensed under the MIT License.
