// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package nsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"time"

	cose "github.com/veraison/go-cose"

	"github.com/provabl/evidence/trust"
)

// Verifier implements the evidence nitro provider's Verifier: it checks that an
// attestation document's COSE_Sign1 signature is valid and that its certificate
// chain (cabundle) anchors to the AWS Nitro root supplied in trust.Root.
//
// It deliberately does NOT check the nonce or PCRs — those are the kernel
// appraiser's job. The Verifier answers exactly one question: "is this a
// genuine, AWS-signed Nitro attestation document?"
type Verifier struct {
	// now is injected for deterministic testing of certificate validity windows;
	// nil means time.Now.
	now func() time.Time
}

// NewVerifier returns a production Verifier.
func NewVerifier() *Verifier { return &Verifier{} }

// Verify reports whether raw is a genuine Nitro attestation document signed under
// the AWS Nitro PKI rooted at root.Material (a PEM-encoded root certificate).
func (v *Verifier) Verify(_ context.Context, raw []byte, root trust.Root) (bool, error) {
	msg, doc, err := Parse(raw)
	if err != nil {
		return false, err
	}

	leaf, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return false, fmt.Errorf("parse leaf certificate: %w", err)
	}

	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(root.Material) {
		return false, fmt.Errorf("trust root %q: no PEM certificate", root.Name)
	}

	// cabundle is [root, interm_1, … interm_N]; the leaf chains through the
	// intermediates to our pinned root. Element 0 is AWS's self-signed root and
	// is not an intermediate, so skip it.
	intermediates := x509.NewCertPool()
	for i, der := range doc.CABundle {
		if i == 0 {
			continue
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return false, fmt.Errorf("parse cabundle[%d]: %w", i, err)
		}
		intermediates.AddCert(c)
	}

	at := time.Now
	if v.now != nil {
		at = v.now
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediates,
		CurrentTime:   at(),
		// AWS disables CRL checking for attestation; the chain is short-lived and
		// pinned. KeyUsages any: these are signing certs, not TLS server certs.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return false, fmt.Errorf("certificate chain does not anchor to %s: %w", root.Name, err)
	}

	// Verify the COSE_Sign1 signature (ES384) against the leaf public key.
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("leaf key is %T, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	coseVerifier, err := cose.NewVerifier(cose.AlgorithmES384, pub)
	if err != nil {
		return false, fmt.Errorf("cose verifier: %w", err)
	}
	if err := msg.Verify(nil, coseVerifier); err != nil {
		return false, fmt.Errorf("COSE_Sign1 signature: %w", err)
	}
	return true, nil
}
