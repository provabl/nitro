// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package nsm

import (
	_ "embed"

	"github.com/provabl/evidence/trust"
)

// awsNitroRootPEM is the AWS Nitro Attestation PKI root certificate for the
// commercial AWS partitions, downloaded from
// https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip.
// Verified SHA256 fingerprint: 64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:
// 7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B, subject CN=aws.nitro-enclaves.
//
//go:embed AWS_NitroEnclaves_Root-G1.pem
var awsNitroRootPEM []byte

// Root returns the AWS Nitro root as a kernel trust.Root, ready to register in a
// trust store under the name the nitro provider resolves (nitro.RootName,
// "aws-nitro"). Material is the embedded root certificate, PEM-encoded.
func Root() trust.Root {
	return trust.Root{Name: "aws-nitro", Material: awsNitroRootPEM}
}
