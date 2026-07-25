package cert

import (
	"bytes"
	"crypto/x509"
	"testing"
)

func TestIssue16SkiFromCertificateRejectsSubjectKeyIDNotDerivedFromPublicKey(t *testing.T) {
	certificate, err := CreateCertificate("unit", "org", "DE", "key-bound-ski")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf.SubjectKeyId = bytes.Repeat([]byte{0x5a}, 20)

	if ski, err := SkiFromCertificate(leaf); err == nil || ski != "" {
		t.Fatalf("mismatched key identifier = %q, %v; want empty SKI and error", ski, err)
	}
}
