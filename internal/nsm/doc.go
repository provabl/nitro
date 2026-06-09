// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

// Package nsm decodes and verifies AWS Nitro Enclave attestation documents and
// adapts them to the provabl/evidence nitro provider's injected Source/Verifier
// interfaces. All COSE/CBOR/X.509 specifics live here so the evidence kernel
// stays stdlib-only.
package nsm

import (
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// AttestationDoc is the CBOR payload of the COSE_Sign1 attestation document, per
// the AWS Nitro spec (docs.aws.amazon.com/enclaves "Verifying the root of trust").
type AttestationDoc struct {
	ModuleID    string          `cbor:"module_id"`
	Timestamp   uint64          `cbor:"timestamp"`
	Digest      string          `cbor:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs"`
	Certificate []byte          `cbor:"certificate"` // leaf cert, DER
	CABundle    [][]byte        `cbor:"cabundle"`    // [root, interm_1, … interm_N], DER
	PublicKey   []byte          `cbor:"public_key"`
	UserData    []byte          `cbor:"user_data"`
	Nonce       []byte          `cbor:"nonce"`
}

// Parse decodes the raw attestation blob into its COSE_Sign1 envelope and the
// CBOR attestation payload. The blob is a (tagged or untagged) COSE_Sign1
// structure whose payload is the CBOR-encoded AttestationDoc.
func Parse(raw []byte) (*cose.Sign1Message, *AttestationDoc, error) {
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(raw); err != nil {
		return nil, nil, fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	var doc AttestationDoc
	if err := cbor.Unmarshal(msg.Payload, &doc); err != nil {
		return nil, nil, fmt.Errorf("decode attestation payload: %w", err)
	}
	return &msg, &doc, nil
}

// pcrsHex renders the PCR map as index-string → lowercase hex, the shape the
// evidence nitro provider's NSMDoc.PCRs expects ("0","1","2","8" → hex SHA384).
func pcrsHex(pcrs map[uint][]byte) map[string]string {
	out := make(map[string]string, len(pcrs))
	for idx, v := range pcrs {
		// Skip all-zero PCRs (debug-mode enclaves emit zeros) — they carry no
		// measurement and would otherwise read as a meaningful value.
		if allZero(v) {
			continue
		}
		out[fmt.Sprintf("%d", idx)] = hex.EncodeToString(v)
	}
	return out
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
