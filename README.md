# nitro

**Runtime/enclave attestation producer for AWS Secure Research Environments.**

Part of the [Provabl](https://provabl.dev) suite:
- **[ground](https://ground.provabl.dev)** — deploy correct AWS foundations
- **[attest](https://attest.provabl.dev)** — compile, enforce, and prove compliance
- **[qualify](https://qualify.provabl.dev)** — train and qualify researchers
- **[vet](https://vet.provabl.dev)** — verify the software supply chain
- **nitro** — attest the runtime: prove the enclave is in a known-good state ← you are here

> Ground your infrastructure, attest your controls, qualify your people, vet your software.

---

## What nitro does

`nitro` is the **producer** for the evidence kernel's runtime-attestation pair. It verifies an
AWS Nitro Enclave attestation document and turns the verdict into the durable outputs the rest of
the suite consumes:

```
enclave NSM document  ──►  nitro  ──►  .nitro/attestation.json   (read by attest → context.platform.*)
                                  └─►  attest:nitro-attested tag  (checked by ground's SCP)
```

It runs the [`provabl/evidence`](https://github.com/provabl/evidence) nitro provider in-process:
the appraiser binds the challenge nonce natively, verifies the COSE_Sign1 signature, and checks
the PCR policy; nitro supplies the real `Source` (the document) and `Verifier` (COSE/CBOR decode +
X.509 chain to the AWS Nitro root) that the stdlib-only kernel leaves injected.

## Verification: the real path

The attestation document is CBOR-encoded and COSE_Sign1-signed (ES384). nitro:

1. decodes the COSE_Sign1 / CBOR object,
2. verifies the certificate chain (`cabundle`) anchors to the **AWS Nitro Attestation PKI root**
   (embedded; SHA256 `64:1A:03:21:…:5B`, `CN=aws.nitro-enclaves`),
3. verifies the document signature against the leaf certificate,
4. hands the parsed `module_id` / nonce / PCRs to the kernel appraiser, which binds the nonce and
   applies the PCR policy.

## Usage

```bash
# Verify a captured attestation document and write .nitro/attestation.json
nitro attest --doc attestation.bin

# Also tag a principal's role when attested (gated by ground's nitro SCP)
nitro attest --doc attestation.bin --role-arn arn:aws:iam::123456789012:role/Workload --region us-east-1

# Require specific enclave measurements
nitro attest --doc attestation.bin --expected-pcr0 7fb5c5…
```

## Document sources

| Source | When | Freshness |
|---|---|---|
| `--doc <file>` | a document captured from an enclave, or AWS's public sample | live doc → `nonce_verified=true`; a sample minted for a different challenge → `nonce_verified=false` (correct: not fresh) |
| `/dev/nsm` device | running **inside** a Nitro enclave | always fresh — the enclave embeds the challenge |

The `/dev/nsm` device source is compiled only under the `nsm` build tag (`make build-nsm`) and runs
**only inside an enclave**. It is compile-checked in CI but cannot be exercised off-enclave.

## Development

```bash
make check       # gofmt + go vet + go test (the device read is excluded)
make build       # build bin/nitro
make build-nsm   # compile-check the enclave-only /dev/nsm source
```

## License

Apache 2.0. Copyright 2026 Scott Friedman.
