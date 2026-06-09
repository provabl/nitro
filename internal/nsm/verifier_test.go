// SPDX-FileCopyrightText: 2026 Scott Friedman
// SPDX-License-Identifier: Apache-2.0

package nsm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"

	"github.com/provabl/evidence/trust"
)

// fixture builds a self-signed AWS-Nitro-shaped attestation: a root CA, a leaf
// signed by it, and a COSE_Sign1 over a CBOR AttestationDoc signed by the leaf.
// It returns the raw COSE_Sign1 bytes and the root as a trust.Root (PEM). This
// exercises the full Verifier path deterministically with no AWS dependency and
// no enclave.
type fixture struct {
	raw     []byte
	root    trust.Root
	nonce   []byte
	leafKey *ecdsa.PrivateKey
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	// Root CA.
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test.nitro-root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)

	// Leaf (the document signing cert), signed by the root.
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test.nitro-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	nonce := []byte("the-issued-challenge-nonce-32byt")
	doc := AttestationDoc{
		ModuleID:    "i-0test.enclave",
		Timestamp:   1_700_000_000_000,
		Digest:      "SHA384",
		PCRs:        map[uint][]byte{0: bytesOf(0x11, 48), 8: bytesOf(0x88, 48)},
		Certificate: leafDER,
		// cabundle is [root, interm…]; here just the root (no intermediates).
		CABundle: [][]byte{rootDER},
		Nonce:    nonce,
	}
	payload, err := cbor.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	// COSE_Sign1 over the payload, signed by the leaf key (ES384).
	signer, err := cose.NewSigner(cose.AlgorithmES384, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES384)
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatal(err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	return fixture{raw: raw, root: trust.Root{Name: "aws-nitro", Material: rootPEM}, nonce: nonce, leafKey: leafKey}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestVerifier_ValidDocument(t *testing.T) {
	f := newFixture(t)
	ok, err := NewVerifier().Verify(context.Background(), f.raw, f.root)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected valid document to verify")
	}
}

func TestVerifier_WrongRootFails(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t) // a different, unrelated root
	ok, err := NewVerifier().Verify(context.Background(), f.raw, other.root)
	if ok {
		t.Fatal("expected verification to fail against an unrelated root")
	}
	if err == nil {
		t.Fatal("expected an error for a chain that does not anchor to the root")
	}
}

func TestVerifier_TamperedPayloadFails(t *testing.T) {
	f := newFixture(t)
	// Flip a byte in the COSE_Sign1 blob — the signature must no longer verify.
	tampered := make([]byte, len(f.raw))
	copy(tampered, f.raw)
	tampered[len(tampered)/2] ^= 0xFF
	ok, _ := NewVerifier().Verify(context.Background(), tampered, f.root)
	if ok {
		t.Fatal("expected tampered document to fail verification")
	}
}

func TestParse_ExtractsFields(t *testing.T) {
	f := newFixture(t)
	doc, err := docFromRaw(f.raw)
	if err != nil {
		t.Fatalf("docFromRaw: %v", err)
	}
	if doc.ModuleID != "i-0test.enclave" {
		t.Errorf("ModuleID = %q", doc.ModuleID)
	}
	if doc.PCRs["0"] == "" || doc.PCRs["8"] == "" {
		t.Errorf("PCRs not parsed: %v", doc.PCRs)
	}
	if string(doc.Nonce) != string(f.nonce) {
		t.Errorf("nonce mismatch")
	}
}

// AWS embeds its real root; confirm it parses as a CA cert with the expected subject.
func TestEmbeddedAWSRoot(t *testing.T) {
	r := Root()
	if r.Name != "aws-nitro" {
		t.Errorf("root name = %q, want aws-nitro", r.Name)
	}
	block, _ := pem.Decode(r.Material)
	if block == nil {
		t.Fatal("embedded root is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse embedded root: %v", err)
	}
	if c.Subject.CommonName != "aws.nitro-enclaves" {
		t.Errorf("embedded root CN = %q, want aws.nitro-enclaves", c.Subject.CommonName)
	}
	if !c.IsCA {
		t.Error("embedded root is not a CA cert")
	}
}
