// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package attestor

import (
	"crypto/ed25519"
	"fmt"

	"github.com/provabl/evidence/trust"
)

const amKeyID = "nitro-am-ephemeral"

// ephemeralAM is the per-run attestation-manager key for the SIG built-in,
// mirroring vet/qualify: in-process Run-then-Appraise, so an ephemeral key is
// sufficient and avoids a key-management surface. The durable artifact is the
// lowered attestation.json, never the evidence bundle.
type ephemeralAM struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
}

func newEphemeralAM() (*ephemeralAM, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("nitro: generate AM key: %w", err)
	}
	return &ephemeralAM{priv: priv, pub: pub, keyID: amKeyID}, nil
}

func (a *ephemeralAM) Sign(msg []byte) ([]byte, string, error) {
	return ed25519.Sign(a.priv, msg), a.keyID, nil
}

// trustStore serves both the AM signing key (for the kernel's SIG spine check)
// and named roots (the aws-nitro root the nitro appraiser resolves for the
// Verifier). It implements trust.Store; the AM implements trust.Signer.
type trustStore struct {
	am    *ephemeralAM
	roots map[string]trust.Root
}

func newTrustStore(am *ephemeralAM, roots ...trust.Root) *trustStore {
	m := make(map[string]trust.Root, len(roots))
	for _, r := range roots {
		m[r.Name] = r
	}
	return &trustStore{am: am, roots: m}
}

func (s *trustStore) Verify(keyID string, msg, sig []byte) (bool, error) {
	if keyID != s.am.keyID {
		return false, nil
	}
	return ed25519.Verify(s.am.pub, msg, sig), nil
}

func (s *trustStore) Root(name string) (trust.Root, bool) {
	r, ok := s.roots[name]
	return r, ok
}
