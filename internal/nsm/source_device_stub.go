// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && nsm)

// Stub DeviceSource for every build that is not the enclave path (no `nsm` tag,
// or not Linux). It keeps the package building everywhere and fails loudly if a
// caller tries to read the NSM device outside an enclave build.

package nsm

import (
	"context"
	"fmt"

	"github.com/provabl/evidence/providers/nitro"
	"github.com/provabl/evidence/term"
)

// DeviceSource is the non-enclave stub. The real /dev/nsm reader is compiled only
// with `-tags nsm` on Linux (see source_device.go).
type DeviceSource struct{}

// Fetch always errors: the NSM device is only available inside a Nitro enclave,
// in a binary built with the `nsm` tag. Use FileSource (--doc) off-enclave.
func (DeviceSource) Fetch(_ context.Context, _ term.Target, _ []byte) (nitro.NSMDoc, error) {
	return nitro.NSMDoc{}, fmt.Errorf("nsm device source not available: build with -tags nsm and run inside a Nitro enclave, or use --doc")
}
