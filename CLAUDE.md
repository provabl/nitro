# nitro — Project Rules

## Overview

nitro is the runtime/enclave attestation **producer** in the Provabl suite. It verifies an AWS
Nitro Enclave attestation document and writes the durable outputs the rest of the suite consumes:
`.nitro/attestation.json` (read by attest as `context.platform.*`) and an `attest:nitro-attested`
IAM principal tag (checked by ground's SCP).

nitro runs the `github.com/provabl/evidence` nitro provider in-process and supplies the real
`Source` + `Verifier` the stdlib-only kernel leaves injected. Appraisal (nonce binding, PCR policy)
is the kernel's job; nitro owns COSE/CBOR decode and X.509 chain verification.

## Architecture

```
cmd/nitro/             — cobra CLI (`nitro attest`)
internal/nsm/          — document parse, embedded AWS root, the Verifier, the Sources
internal/attestor/     — run the kernel → write .nitro/attestation.json + the IAM tag
```

- **internal/nsm** owns all crypto: COSE_Sign1/CBOR decode (`veraison/go-cose`, `fxamacker/cbor`),
  the embedded `AWS_NitroEnclaves_Root-G1.pem`, chain verification (`crypto/x509`), and the
  document Sources (file; `/dev/nsm` device behind the `nsm` build tag).
- **internal/attestor** mirrors vet's `gate.Evaluate` (run kernel → lower → write artifact) and
  qualify's `tagRole` (write the IAM tag through an injected `iamTagWriter`).

## Hard rules

1. **The evidence kernel stays a dependency, never the reverse.** nitro imports
   `github.com/provabl/evidence`; the kernel never imports nitro. All COSE/CBOR/X.509 deps live here.
2. **The Verifier attests signature + chain only.** Nonce binding and PCR policy belong to the
   kernel appraiser, not the Verifier. Don't duplicate them.
3. **The `/dev/nsm` device read is enclave-only.** The ioctl is wired (and was validated on real
   Nitro hardware — see nitro#4) but lives behind `//go:build linux && nsm` with a stub for every
   other build, is compile-checked (`make build-nsm`) but never *run* in CI, and must never be in
   the default build path. The parse path is exercisable offline via the captured
   `internal/nsm/testdata/real-attestation.bin` fixture.
4. **Tag keys come from the contract, not literals scattered in code.** `attest:nitro-attested`
   matches ground's SCP and attest's `PlatformAttributes`; keep it defined once.
5. **The artifact shape matches attest's `PlatformAttributes` json tags** (`nitro_attested`,
   `module_id`, `nonce_verified`, `signature_valid`, `pcr0/1/2/8`). It is a JSON contract, not a
   shared Go type — keep the mapping in one chokepoint.

## Go conventions

- Go 1.26.4. Module `github.com/provabl/nitro`. SPDX header on every `.go` file.
- No `init()`, no global mutable state. Errors wrapped (`fmt.Errorf("…: %w", err)`).
- Injected interfaces for the Source, Verifier, and IAM tagger so everything tests with no
  network and no enclave.
- `make check` (gofmt + vet + test) before committing; CI runs the same Makefile targets.
- Semantic versioning; CHANGELOG per keepachangelog 1.1.0; cosign-signed releases.
- Branches: `feat/<desc>`; main always releasable.
