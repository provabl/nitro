// SPDX-FileCopyrightText: 2026 Playground Logic LLC
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

// coseSign1Tag is the CBOR tag (18) that prefixes a tagged COSE_Sign1 structure.
// Encoded as a head byte it is 0xd2 (major type 6, value 18).
const coseSign1Tag = 0xd2

// untaggedSign1Head is the CBOR head byte of an UNTAGGED COSE_Sign1: an array of
// four elements (0x80 | 4). AWS's NSM device returns the attestation document in
// this untagged form, but veraison/go-cose's UnmarshalCBOR only accepts the
// tagged form — so a real on-device document must be tag-wrapped before decoding.
// (Confirmed on real Nitro hardware: the captured document begins 0x84, and
// UnmarshalCBOR rejects it with "invalid COSE_Sign1_Tagged object" until the
// tag is prepended. See testdata/real-attestation.bin and nitro#4.)
const untaggedSign1Head = 0x84

// Parse decodes the raw attestation blob into its COSE_Sign1 envelope and the
// CBOR attestation payload. The blob is a tagged or untagged COSE_Sign1 structure
// whose payload is the CBOR-encoded AttestationDoc; an untagged blob (what the NSM
// device emits) is normalized to the tagged form go-cose requires.
func Parse(raw []byte) (*cose.Sign1Message, *AttestationDoc, error) {
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("decode COSE_Sign1: empty document")
	}
	// Normalize an untagged COSE_Sign1 (array(4), head 0x84) to the tagged form by
	// prepending the COSE_Sign1 tag, which is what go-cose's decoder expects.
	if raw[0] == untaggedSign1Head {
		tagged := make([]byte, 0, len(raw)+1)
		tagged = append(tagged, coseSign1Tag)
		raw = append(tagged, raw...)
	}
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
