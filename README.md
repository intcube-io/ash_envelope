![Logo](https://github.com/ash-project/ash/blob/main/logos/cropped-for-header-black-text.png?raw=true#gh-light-mode-only)
![Logo](https://github.com/ash-project/ash/blob/main/logos/cropped-for-header-white-text.png?raw=true#gh-dark-mode-only)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hex version badge](https://img.shields.io/hexpm/v/ash_envelope.svg)](https://hex.pm/packages/ash_envelope)
[![Hexdocs badge](https://img.shields.io/badge/docs-hexdocs-purple)](https://hexdocs.pm/ash_envelope)

# AshEnvelope

AshEnvelope provides envelope encryption primitives and key grant management for the [Ash](https://hexdocs.pm/ash) ecosystem.

It uses AES-256-GCM for encryption with random IVs and authentication tags, and supports multi-recipient key management through a grants table pattern.

## Features

- **AES-256-GCM encryption/decryption** for arbitrary data
- **DEK wrapping/unwrapping** for envelope encryption schemes
- **Key Grants** for multi-recipient scenarios (share/revoke access)
- **BlobIO KeyManagers** (`Asymmetric`, `KeyGrants`) for encrypting `AshStorage` attachments
- **Backup-key escrow** (opt-in) with a dedicated rotation Mix task and a fail-on-incomplete check
- **Reconciliation** keeps grants in sync with the encrypted resource's `:read` policy
- **Mix task generators** for scaffolding key grants and grant-request infrastructure

## Tutorials

- [Getting Started with AshEnvelope](documentation/tutorials/getting-started-with-ash-envelope.md)

## Topics

- [How Envelope Encryption Works](documentation/topics/how-envelope-encryption-works.md)
- [Reconciliation](documentation/topics/reconciliation.md)
- [Expiring Grants](documentation/topics/expiring-grants.md)
- [User-driven fulfillment](documentation/topics/user-driven-fulfillment.md)

## Reference

- [AshEnvelope API](https://hexdocs.pm/ash_envelope)
