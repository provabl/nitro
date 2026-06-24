// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	_ "embed"
	"encoding/json"
	"testing"
)

// canonicalTagsSchemaJSON is the byte-identical copy of the suite's canonical
// attest:* tag registry (source of truth: provabl/attest pkg/schema, mirrored in
// qualify). Per provabl ADR 0003, each writer repo locks ITS OWN rows to the
// registry so a tag rename fails that writer's CI rather than silently in
// production. nitro is the writer of attest:enclave-attested.
//
//go:embed attest-tags-schema.json
var canonicalTagsSchemaJSON []byte

type tagRow struct {
	Key    string `json:"key"`
	Writer string `json:"writer"`
	Type   string `json:"type"`
}

type tagRegistry struct {
	Tags []tagRow `json:"tags"`
}

// TestEnclaveTagMatchesRegistry locks nitro's tag constant to the canonical
// registry's nitro-writer row. If the registry renames the tag (or nitro's const
// drifts), this fails — the writer-scoped conformance guard from ADR 0003.
func TestEnclaveTagMatchesRegistry(t *testing.T) {
	var reg tagRegistry
	if err := json.Unmarshal(canonicalTagsSchemaJSON, &reg); err != nil {
		t.Fatalf("parse canonical registry: %v", err)
	}

	var nitroRows []tagRow
	for _, r := range reg.Tags {
		if r.Writer == "nitro" {
			nitroRows = append(nitroRows, r)
		}
	}

	// nitro writes exactly one tag today: attest:enclave-attested.
	if len(nitroRows) != 1 {
		t.Fatalf("registry has %d writer=nitro rows, want 1: %+v", len(nitroRows), nitroRows)
	}
	if nitroRows[0].Key != TagEnclaveAttested {
		t.Errorf("registry nitro tag = %q, but TagEnclaveAttested = %q — they must match (ADR 0003)",
			nitroRows[0].Key, TagEnclaveAttested)
	}
	if nitroRows[0].Type != "bool" {
		t.Errorf("attest:enclave-attested type = %q, want bool", nitroRows[0].Type)
	}

	// Guard against the pre-split conflated tag reappearing.
	for _, r := range reg.Tags {
		if r.Key == "attest:nitro-attested" {
			t.Error("registry still contains attest:nitro-attested — it was split into enclave/boot-attested (ADR 0003)")
		}
	}
}
