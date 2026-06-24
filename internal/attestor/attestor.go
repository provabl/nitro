// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package attestor runs the provabl/evidence nitro provider against a document
// source and turns the verdict into the suite's durable outputs: a
// .nitro/attestation.json file (read by attest as context.platform.*) and the
// attest:enclave-attested IAM principal tag (checked by ground's SCP).
package attestor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/provabl/evidence/asp"
	"github.com/provabl/evidence/cvm"
	"github.com/provabl/evidence/lower"
	nitroprov "github.com/provabl/evidence/providers/nitro"
	"github.com/provabl/evidence/term"

	"github.com/provabl/nitro/internal/nsm"
)

// TagEnclaveAttested is the IAM principal tag ground's SCP checks for ENCLAVE
// attestation: it asserts the principal is running inside a verified Nitro
// Enclave. It is deliberately distinct from tpm's attest:boot-attested (measured
// OS boot) — a tag names what was proven, not which tool proved it, and the two
// are different trust strengths (no conflation). See provabl ADR 0003 and the
// canonical attest:* registry (attest-tags-schema.json, writer "nitro").
const TagEnclaveAttested = "attest:enclave-attested"

// PlatformResult is the .nitro/attestation.json artifact. Its json tags match
// attest's schema.PlatformAttributes (the context.platform.* contract) — a JSON
// shape, not a shared Go type, so the two version independently.
type PlatformResult struct {
	NitroAttested  bool   `json:"nitro_attested"`
	ModuleID       string `json:"module_id"`
	NonceVerified  bool   `json:"nonce_verified"`
	SignatureValid bool   `json:"signature_valid"`
	PCR0           string `json:"pcr0"`
	PCR1           string `json:"pcr1"`
	PCR2           string `json:"pcr2"`
	PCR8           string `json:"pcr8"`
}

// IAMTagger writes tags to an IAM role. Implemented by the AWS IAM client in
// production; mocked in tests. Mirrors qualify's iamTagWriter.
type IAMTagger interface {
	TagRole(ctx context.Context, roleName string, tags map[string]string) error
}

// Attestor produces attestation outputs from a document source.
type Attestor struct {
	src      nitroprov.Source
	ver      nitroprov.Verifier
	tagger   IAMTagger // optional; nil = no IAM tagging
	nitroDir string
}

// New builds an Attestor. nitroDir defaults to ".nitro". tagger may be nil.
func New(src nitroprov.Source, ver nitroprov.Verifier, tagger IAMTagger, nitroDir string) *Attestor {
	if nitroDir == "" {
		nitroDir = ".nitro"
	}
	return &Attestor{src: src, ver: ver, tagger: tagger, nitroDir: nitroDir}
}

// Result is the outcome of an attestation run.
type Result struct {
	Platform   PlatformResult
	Reason     string
	WrotePath  string
	TaggedRole string // non-empty if an IAM tag was written
}

// Attest runs the nitro provider for the target through the evidence kernel,
// lowers the verdict, writes .nitro/attestation.json, and — when attested and a
// roleARN is given — writes the attest:enclave-attested tag to that role.
//
// expectedPCRs maps PCR index ("0","8") → expected hex value; each becomes an
// expected_pcr<N> appraiser param.
func (a *Attestor) Attest(ctx context.Context, roleARN string, expectedPCRs map[string]string) (*Result, error) {
	reg := asp.NewRegistry()
	if err := reg.Register(nitroprov.Provider(a.src, a.ver)); err != nil {
		return nil, fmt.Errorf("register nitro provider: %w", err)
	}
	am, err := newEphemeralAM()
	if err != nil {
		return nil, err
	}
	store := newTrustStore(am, nsm.Root())
	c := cvm.New(reg, am, store, nil)

	params := term.Params{}
	for idx, want := range expectedPCRs {
		params["expected_pcr"+idx] = want
	}

	protocol := term.Seq(
		term.Nonce(),
		term.Seq(
			term.Meas(term.Self, nitroprov.ID, term.Target("nitro://self"), params),
			term.Sig(),
		),
	)
	bundle, ch, err := c.Run(ctx, protocol)
	if err != nil {
		return nil, fmt.Errorf("run attestation: %w", err)
	}
	verdict, err := c.Appraise(ctx, bundle, ch)
	if err != nil {
		return nil, fmt.Errorf("appraise: %w", err)
	}

	attrs := lower.ToAttributes(verdict)
	res := &Result{Platform: platformFromAttrs(attrs, verdict.Pass), Reason: verdict.Reason}

	path, err := a.write(res.Platform)
	if err != nil {
		return nil, err
	}
	res.WrotePath = path

	if res.Platform.NitroAttested && roleARN != "" && a.tagger != nil {
		roleName := roleNameFromARN(roleARN)
		if roleName == "" {
			return nil, fmt.Errorf("could not extract role name from ARN: %s", roleARN)
		}
		if err := a.tagger.TagRole(ctx, roleName, map[string]string{TagEnclaveAttested: "true"}); err != nil {
			return nil, fmt.Errorf("tag role %s: %w", roleName, err)
		}
		res.TaggedRole = roleName
	}
	return res, nil
}

// platformFromAttrs is the single chokepoint mapping lowered kernel attributes
// into the artifact. Absent platform.* attributes (CollectFailed) default to
// zero/false — a fail-closed result.
func platformFromAttrs(attrs map[string]lower.Attr, pass bool) PlatformResult {
	b := func(k string) bool { return attrs["platform."+k].Value == "true" }
	return PlatformResult{
		NitroAttested:  pass && b("nitro_attested"),
		ModuleID:       attrs["platform.module_id"].Value,
		NonceVerified:  b("nonce_verified"),
		SignatureValid: b("signature_valid"),
		PCR0:           attrs["platform.pcr0"].Value,
		PCR1:           attrs["platform.pcr1"].Value,
		PCR2:           attrs["platform.pcr2"].Value,
		PCR8:           attrs["platform.pcr8"].Value,
	}
}

func (a *Attestor) write(p PlatformResult) (string, error) {
	if err := os.MkdirAll(a.nitroDir, 0o750); err != nil {
		return "", fmt.Errorf("create %s: %w", a.nitroDir, err)
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal attestation: %w", err)
	}
	path := filepath.Join(a.nitroDir, "attestation.json")
	if err := os.WriteFile(path, data, 0o640); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// roleNameFromARN extracts the role name from an IAM role ARN
// ("arn:aws:iam::123456789012:role/My-Role" → "My-Role").
func roleNameFromARN(arn string) string {
	const sep = ":role/"
	i := strings.LastIndex(arn, sep)
	if i == -1 {
		return ""
	}
	return arn[i+len(sep):]
}
