// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

//go:build linux && nsm

// This file is compiled only with the `nsm` build tag and only on Linux. The NSM
// device exists only inside a running AWS Nitro Enclave, so this path cannot be
// exercised off-enclave; CI compile-checks it via `make build-nsm` but never runs
// it. Build the producer with: go build -tags nsm ./...

package nsm

import (
	"context"
	"fmt"
	"os"

	"github.com/provabl/evidence/providers/nitro"
	"github.com/provabl/evidence/term"
)

// nsmDevice is the Nitro Security Module character device available inside an
// enclave.
const nsmDevice = "/dev/nsm"

// DeviceSource requests a fresh attestation document from the enclave's NSM
// device, embedding the run's challenge nonce so the kernel appraiser can bind it.
type DeviceSource struct{}

// Fetch implements nitro.Source by issuing an NSM Attestation request over
// /dev/nsm with the given nonce and parsing the returned COSE_Sign1 document.
//
// NOTE: the concrete NSM ioctl request/response framing (the CBOR-wrapped
// Attestation request and the device ioctl) is intentionally minimal here and
// must be completed against the live NSM API when first run on real Nitro
// hardware. AWS ships no Go NSM SDK, so this is the integration seam; it is
// compiled but unverified until exercised inside an enclave.
func (DeviceSource) Fetch(_ context.Context, _ term.Target, nonce []byte) (nitro.NSMDoc, error) {
	f, err := os.OpenFile(nsmDevice, os.O_RDWR, 0)
	if err != nil {
		return nitro.NSMDoc{}, fmt.Errorf("open %s (are we inside a Nitro enclave?): %w", nsmDevice, err)
	}
	defer func() { _ = f.Close() }()

	raw, err := nsmAttest(f, nonce)
	if err != nil {
		return nitro.NSMDoc{}, fmt.Errorf("nsm attestation request: %w", err)
	}
	return docFromRaw(raw)
}
