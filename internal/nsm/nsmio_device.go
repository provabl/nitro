// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build linux && nsm

package nsm

import (
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
)

// nsmAttest issues an Attestation request to the NSM device and returns the raw
// COSE_Sign1 attestation document.
//
// The NSM device speaks a CBOR-framed request/response protocol over an ioctl
// (see github.com/aws/aws-nitro-enclaves-nsm-api). The request is
// {"Attestation": {"nonce": <bytes>, "user_data": null, "public_key": null}};
// the response is {"Attestation": {"document": <COSE_Sign1 bytes>}}. The exact
// ioctl number and the iovec framing are NSM-driver specifics that must be
// confirmed on real Nitro hardware — this is the one seam that cannot be
// validated off-enclave. It is intentionally explicit about that rather than
// pretending to be verified.
func nsmAttest(_ *os.File, nonce []byte) ([]byte, error) {
	// Build the CBOR request the NSM driver expects.
	req := map[string]any{
		"Attestation": map[string]any{
			"nonce":      nonce,
			"user_data":  nil,
			"public_key": nil,
		},
	}
	if _, err := cbor.Marshal(req); err != nil {
		return nil, fmt.Errorf("marshal nsm request: %w", err)
	}
	// The ioctl exchange against /dev/nsm is completed when first run on real
	// Nitro hardware; AWS publishes no Go binding for it. Until then this returns
	// a clear, non-silent error so a non-enclave invocation never looks like a
	// successful (but empty) attestation.
	return nil, fmt.Errorf("nsm: device ioctl not yet wired — run inside a Nitro enclave with a completed nsmAttest, or use --doc")
}
