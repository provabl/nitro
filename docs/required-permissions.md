# nitro — required AWS permissions

`nitro preflight` verifies the calling AWS principal holds these actions, using
read-only `iam:SimulatePrincipalPolicy` against the caller ARN (from
`sts:GetCallerIdentity`). It **evaluates, it never acts** — running preflight changes
nothing. A denied action prints a remediation and the command exits non-zero.

Most of what nitro does **needs no AWS at all**. Verifying an attestation document —
whether captured (`--doc`) or read fresh from `/dev/nsm` (`--device`, inside a Nitro
enclave) — is a local COSE/CBOR decode plus an X.509 chain check to the embedded AWS
Nitro Attestation PKI root, and the verdict is always written locally to
`.nitro/attestation.json` (attest reads it as `context.platform.*`). No AWS API touches
that path. The one AWS-touching path is below.

| Action | Needed by | Status |
|--------|-----------|--------|
| `sts:GetCallerIdentity` | preflight itself (resolves the caller ARN to simulate) | live |
| `iam:SimulatePrincipalPolicy` | preflight itself (the permission self-check) | live |
| `iam:TagRole` | `nitro attest --role-arn` — write the `attest:enclave-attested` IAM role tag on the attested principal's role after a successful verify (ground's SCP gates on it) | live |

`iam:TagRole` is exercised **only** when you pass `--role-arn` and the document
actually attests. Without `--role-arn`, nitro verifies and writes
`.nitro/attestation.json` and touches no IAM — so a principal that only ever runs the
local verify needs nothing beyond credentials to read the document.

> **Note — `--expected-from-ami` reads, but isn't checked here.** When `nitro attest`
> runs on a live instance with `--expected-from-ami`, it loads the golden PCRs from the
> source AMI's `attest:pcr*` tags via IMDS + `ec2:DescribeImages`. That is an
> instance-role, read-only convenience path (the same tags `vet ami-reference` records),
> not part of nitro's permission contract, so preflight does not simulate it. If you use
> the flag, grant the instance role `ec2:DescribeImages`.

## Why preflight checks `iam:TagRole` even when you don't tag

The check is read-only, and over-provisioning a *simulation* costs nothing. Listing
`iam:TagRole` lets an operator confirm the nitro principal is ready to write the
`attest:enclave-attested` tag **before** running an attest-and-tag flow, rather than
discovering a missing grant when the tag write fails mid-way. To scope a principal to
only the local verify path, grant `sts:GetCallerIdentity` +
`iam:SimulatePrincipalPolicy` (preflight) and nothing else — the document verification
needs no AWS.

## Boundary

nitro **produces and tags; it never decides access.** It verifies a Nitro **enclave**
attestation document and lowers the verdict into `.nitro/attestation.json`
(`context.platform.*`) plus the `attest:enclave-attested` tag — attest's Cedar PDP and
ground's SCP are what gate on those. The tag means *running inside a verified Nitro
enclave* and is deliberately distinct from tpm's `attest:boot-attested` (measured-OS
boot) — not conflated (provabl ADR 0003). The trust anchor is the embedded AWS Nitro
Attestation PKI root, and freshness is real only on a live `--device` read; see the
README's trust model and provabl ADR 0003.
