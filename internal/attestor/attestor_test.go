// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/provabl/evidence/providers/nitro"
	"github.com/provabl/evidence/term"
	"github.com/provabl/evidence/trust"
)

// echoSource returns a fabricated NSMDoc echoing the run's challenge as the
// document nonce (what a real enclave does) so the kernel appraiser binds it.
type echoSource struct {
	pcrs     map[string]string
	fetchErr error
}

func (s echoSource) Fetch(_ context.Context, _ term.Target, nonce []byte) (nitro.NSMDoc, error) {
	if s.fetchErr != nil {
		return nitro.NSMDoc{}, s.fetchErr
	}
	return nitro.NSMDoc{
		ModuleID: "i-0test.enclave",
		Nonce:    nonce,
		PCRs:     s.pcrs,
		Raw:      []byte("fixture-cose"),
	}, nil
}

// okVerifier / badVerifier stand in for the real COSE/X.509 Verifier.
type okVerifier struct{}

func (okVerifier) Verify(context.Context, []byte, trust.Root) (bool, error) { return true, nil }

type badVerifier struct{}

func (badVerifier) Verify(context.Context, []byte, trust.Root) (bool, error) { return false, nil }

// mockTagger records the tag write.
type mockTagger struct {
	calls    int
	roleName string
	tags     map[string]string
}

func (m *mockTagger) TagRole(_ context.Context, roleName string, tags map[string]string) error {
	m.calls++
	m.roleName = roleName
	m.tags = tags
	return nil
}

func TestAttest_AttestedWritesArtifactAndTag(t *testing.T) {
	dir := t.TempDir()
	tagger := &mockTagger{}
	a := New(echoSource{pcrs: map[string]string{"0": "aa", "8": "dd"}}, okVerifier{}, tagger, dir)

	res, err := a.Attest(context.Background(), "arn:aws:iam::123456789012:role/Workload", nil)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if !res.Platform.NitroAttested {
		t.Fatalf("expected attested, reason: %s", res.Reason)
	}
	if !res.Platform.NonceVerified || !res.Platform.SignatureValid {
		t.Errorf("expected nonce+signature verified: %+v", res.Platform)
	}

	// Artifact written with the context.platform.* json shape.
	data, err := os.ReadFile(filepath.Join(dir, "attestation.json"))
	if err != nil {
		t.Fatalf("read artifact: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("artifact not valid JSON: %v", err)
	}
	if out["nitro_attested"] != true || out["pcr0"] != "aa" {
		t.Errorf("artifact wrong: %v", out)
	}

	// Tag written.
	if tagger.calls != 1 || tagger.tags[TagEnclaveAttested] != "true" {
		t.Errorf("expected one %s=true tag write, got calls=%d tags=%v", TagEnclaveAttested, tagger.calls, tagger.tags)
	}
	if tagger.roleName != "Workload" {
		t.Errorf("role name = %q, want Workload", tagger.roleName)
	}
}

func TestAttest_PCRMismatchNotAttestedNoTag(t *testing.T) {
	dir := t.TempDir()
	tagger := &mockTagger{}
	a := New(echoSource{pcrs: map[string]string{"0": "aa"}}, okVerifier{}, tagger, dir)

	// Require a different PCR0 than the doc carries.
	res, err := a.Attest(context.Background(), "arn:aws:iam::123456789012:role/Workload",
		map[string]string{"0": "deadbeef"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if res.Platform.NitroAttested {
		t.Fatal("expected not attested on PCR mismatch")
	}
	if tagger.calls != 0 {
		t.Errorf("expected no tag write when not attested, got %d", tagger.calls)
	}
	// Artifact is still written (fail-closed record).
	if _, err := os.Stat(filepath.Join(dir, "attestation.json")); err != nil {
		t.Errorf("expected artifact written even when not attested: %v", err)
	}
}

func TestAttest_BadSignatureNoTag(t *testing.T) {
	dir := t.TempDir()
	tagger := &mockTagger{}
	a := New(echoSource{pcrs: map[string]string{"0": "aa"}}, badVerifier{}, tagger, dir)

	res, err := a.Attest(context.Background(), "arn:aws:iam::123456789012:role/Workload", nil)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if res.Platform.NitroAttested {
		t.Fatal("expected not attested on bad signature")
	}
	if res.Platform.SignatureValid {
		t.Error("expected signature_valid=false")
	}
	if tagger.calls != 0 {
		t.Errorf("expected no tag write, got %d", tagger.calls)
	}
}

func TestRoleNameFromARN(t *testing.T) {
	if got := roleNameFromARN("arn:aws:iam::123456789012:role/My-Role"); got != "My-Role" {
		t.Errorf("got %q, want My-Role", got)
	}
	if got := roleNameFromARN("not-an-arn"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}
