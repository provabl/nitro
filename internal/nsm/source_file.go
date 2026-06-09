// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package nsm

import (
	"context"
	"fmt"
	"os"

	"github.com/provabl/evidence/providers/nitro"
	"github.com/provabl/evidence/term"
)

// FileSource reads an attestation document captured from an enclave (or AWS's
// public sample) from a file and adapts it to the kernel's nitro.Source. The
// nonce it returns is whatever the document embeds — for a live document that is
// the challenge the enclave was given; for a sample minted elsewhere it will not
// match a fresh challenge, and the kernel appraiser will correctly report
// nonce_verified=false.
type FileSource struct {
	Path string
}

// Fetch implements nitro.Source. The nonce argument (the run's challenge) is not
// used here: a file source cannot re-mint the document, so freshness is judged by
// the kernel against whatever nonce the document actually carries.
func (s FileSource) Fetch(_ context.Context, _ term.Target, _ []byte) (nitro.NSMDoc, error) {
	raw, err := os.ReadFile(s.Path) // #nosec G304 — operator-supplied document path
	if err != nil {
		return nitro.NSMDoc{}, fmt.Errorf("read attestation document %q: %w", s.Path, err)
	}
	return docFromRaw(raw)
}

// docFromRaw parses a raw attestation blob into the kernel's NSMDoc. Shared by the
// file source and the (enclave-only) device source.
func docFromRaw(raw []byte) (nitro.NSMDoc, error) {
	_, doc, err := Parse(raw)
	if err != nil {
		return nitro.NSMDoc{}, err
	}
	return nitro.NSMDoc{
		ModuleID:  doc.ModuleID,
		Nonce:     doc.Nonce,
		PCRs:      pcrsHex(doc.PCRs),
		Timestamp: int64(doc.Timestamp),
		Raw:       raw,
	}, nil
}
