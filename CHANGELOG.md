# Changelog

All notable changes to nitro will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Copyright holder normalized to Playground Logic LLC.

## [0.1.0] - 2026-06-09

### Added

- **The nitro attestation producer** — runs the `provabl/evidence` nitro provider in-process and
  writes the durable outputs the suite consumes, closing the runtime-attestation loop end to end.
- **`internal/nsm`** — the production `Source` and `Verifier` the stdlib-only kernel leaves
  injected: COSE_Sign1 / CBOR decode (`veraison/go-cose`, `fxamacker/cbor`), the embedded **AWS
  Nitro Attestation PKI root** (`AWS_NitroEnclaves_Root-G1.pem`, SHA256 `64:1A:03:21:…:5B`), X.509
  `cabundle` chain verification to that root, and the COSE signature check against the leaf. A
  file-based document source, plus a `/dev/nsm` device source behind the `nsm` build tag
  (enclave-only; compile-checked, never run in CI).
- **`internal/attestor`** — runs the kernel term, lowers the verdict, writes
  `.nitro/attestation.json` (matching attest's `context.platform.*` shape), and writes the
  `attest:nitro-attested` IAM principal tag (checked by ground's SCP) through an injected tagger.
- **`nitro attest`** CLI — verify a document, write the artifact, optionally tag a role.

[Unreleased]: https://github.com/provabl/nitro/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/provabl/nitro/releases/tag/v0.1.0
