// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package nsm

import (
	"os"
	"testing"
)

// realAttestation is a genuine AWS Nitro Enclave attestation document captured
// from /dev/nsm on real hardware (m5.xlarge, us-west-2) while validating the
// device ioctl for nitro#4. The request nonce was the ASCII string below. It is
// an UNTAGGED COSE_Sign1 (first byte 0x84) — the form the NSM device emits and
// the regression this test pins: go-cose's decoder rejects it until Parse
// tag-normalizes it.
const realAttestationNonce = "provabl-nitro4-validation-nonce!"

func TestParse_RealUntaggedAttestation(t *testing.T) {
	raw, err := os.ReadFile("testdata/real-attestation.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// Guard the premise: the captured document is untagged (array(4), 0x84). If a
	// future re-capture is tagged (0xd2), this test's point is moot — fail loudly
	// so the fixture/intent is revisited rather than silently weakened.
	if raw[0] != untaggedSign1Head {
		t.Fatalf("fixture first byte = 0x%02x, expected an untagged COSE_Sign1 (0x84)", raw[0])
	}

	msg, doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse real untagged attestation: %v", err)
	}
	if msg == nil || len(msg.Payload) == 0 {
		t.Fatal("expected a decoded COSE_Sign1 with a non-empty payload")
	}

	// Native nonce binding: the document echoes exactly the challenge the enclave
	// program embedded in the ioctl request.
	if string(doc.Nonce) != realAttestationNonce {
		t.Errorf("nonce = %q, want %q", string(doc.Nonce), realAttestationNonce)
	}
	if doc.ModuleID == "" {
		t.Error("expected a non-empty module_id")
	}
	if len(doc.PCRs) == 0 {
		t.Error("expected at least one PCR")
	}
	if len(doc.Certificate) == 0 {
		t.Error("expected a leaf certificate")
	}
	if len(doc.CABundle) == 0 {
		t.Error("expected a CA bundle chaining toward the AWS Nitro root")
	}
}

// TestParse_RejectsEmpty ensures the length guard fires before indexing raw[0].
func TestParse_RejectsEmpty(t *testing.T) {
	if _, _, err := Parse(nil); err == nil {
		t.Fatal("expected an error for an empty document")
	}
}
