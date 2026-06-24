# Changelog

All notable changes to nitro will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`nitro attest --expected-from-ami`** (provabl#13): on the live instance, auto-loads the expected
  PCRs from the source AMI's `attest:pcr<N>` golden tags (the ones `vet ami-reference` writes) instead
  of the operator hand-copying hex into `--expected-pcrN`. Reads the source AMI id from IMDS
  (`ami-id`) and the tags via `ec2:DescribeImages`, feeding them to the `expected_pcr<N>` appraiser
  check — so an instance whose measured boot diverges from the vetted image's golden reference fails
  attestation. Explicit `--expected-pcrN` flags override the AMI-derived values; a source AMI with no
  `attest:pcr*` tags is an error (fail-closed, not an unenforced check). The golden tags are locked to
  the vetter by ground's lockdown SCP, so an instance cannot rewrite its own reference. New
  `internal/goldenpcr` (IMDS + DescribeImages behind interfaces; fake-driven tests). Closes the
  runtime-binding loop's last manual seam.
- **`nitro preflight`** (provabl#16): verifies the calling principal holds the IAM action nitro needs
  (`iam:TagRole`, to write `attest:nitro-attested`) via read-only `iam:SimulatePrincipalPolicy`
  against the caller ARN. Renders ✓/✗ per action with remediation; exits non-zero on any deny;
  fail-closed on an un-callable check. New `internal/preflight` (mock-driven tests). Mirrors
  attest/ground; each suite tool carries its own copy. See `docs/required-permissions.md`.
- **Live `/dev/nsm` device read** (closes #4): `nsmAttest` now issues the real NSM ioctl
  (`_IOWR(0x0A, 0, …)` over a two-iovec `nsm_message`, cross-checked against `github.com/hf/nsm`),
  decodes the `{"Attestation": {"document": …}}` response, and returns the live COSE_Sign1
  attestation document. `nitro attest --device` reads a fresh, nonce-bound document from `/dev/nsm`
  inside an enclave (vs `--doc` for a captured file). **Validated on real Nitro hardware** (m5.xlarge,
  us-west-2): the ioctl returned a 4493-byte document binding the supplied challenge nonce.

### Fixed

- **Untagged COSE_Sign1 from the NSM device** (#4): the NSM device emits an *untagged* COSE_Sign1
  (CBOR array, head `0x84`), which `veraison/go-cose` rejected (`invalid COSE_Sign1_Tagged object`)
  — so the live document never parsed, a bug only reachable on real hardware. `Parse` now normalizes
  an untagged document to the tagged form before decoding. Regression-pinned by
  `internal/nsm/testdata/real-attestation.bin`, a genuine document captured from an enclave.

### Changed

- **nitro now writes `attest:enclave-attested`** (was the conflated `attest:nitro-attested`), per
  provabl ADR 0003 / provabl#30 (nitro#10). The enclave producer and the boot producer (`tpm`)
  previously wrote the same `attest:nitro-attested` tag, but they prove different properties at
  different trust strengths — nitro proves a verified Nitro **Enclave**, tpm proves a measured OS
  **boot** (NitroTPM). The conflated tag is split per property: nitro writes `attest:enclave-attested`,
  tpm writes `attest:boot-attested`. A tag names what was proven, not which tool proved it. A
  writer-scoped conformance test (`internal/attestor/schema_conformance_test.go`, embedding the
  canonical `attest-tags-schema.json` v3) locks nitro's constant to the registry's `writer:"nitro"`
  row and fails if the pre-split tag reappears. `TagNitroAttested` → `TagEnclaveAttested`.
- **SLSA L3 release provenance** (provabl#5): `release.yml` now generates provenance via the
  `slsa-framework/slsa-github-generator` reusable workflow (isolated, non-falsifiable builder)
  instead of `actions/attest-build-provenance` (L2). One runner cross-compiles all targets and emits
  a combined `hashes` output for the generator; cosign signatures + attested SBOM retained. The L3
  proof is produced on the next tag.
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
