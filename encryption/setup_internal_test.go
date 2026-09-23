package encryption

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

// testFixtureCert parse a certificate fixture
func testFixtureCert(t *testing.T, name string) *x509.Certificate {
	assert := assert.New(t)

	content, err := os.ReadFile(filepath.Join("..", "test", "certs", name))
	assert.Nil(err)
	block, _ := pem.Decode(content)
	assert.NotNil(block)
	cert, err := x509.ParseCertificate(block.Bytes)
	assert.Nil(err)

	return cert
}

// testFixtureBytes read a fixture verbatim
func testFixtureBytes(t *testing.T, name string) []byte {
	content, err := os.ReadFile(filepath.Join("..", "test", "certs", name))
	assert.New(t).Nil(err)
	return content
}

// TestVerifyCertificateMalformedCABundle verifies how a CA bundle which is not a usable set
// of certificates is reported.
//
// The bundle is operator supplied, so these are the shapes a misconfiguration takes. Each
// has to name what is wrong with the bundle rather than surface as a chain failure, which
// would send the reader looking at the wrong file.
func TestVerifyCertificateMalformedCABundle(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	now := time.Now().UTC()
	cert := testFixtureCert(t, "user-root.crt")

	tests := []struct {
		name    string
		bundle  []byte
		expects string
	}{
		{
			name:    "no PEM blocks at all",
			bundle:  []byte("this file holds no PEM blocks\n"),
			expects: "CA bundle contains no certificates",
		},
		{
			name:    "only a non-certificate PEM block",
			bundle:  testFixtureBytes(t, "self-signed.key"),
			expects: "CA bundle contains no certificates",
		},
		{
			name: "a certificate block holding unparseable DER",
			bundle: pem.EncodeToMemory(
				&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a DER encoded certificate")},
			),
			expects: "failed to parse CA bundle certificate 0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)

			err := verifyCertificate(cert, test.bundle, now)
			assert.Error(err)
			assert.ErrorContains(err, test.expects)
		})
	}
}

// TestVerifyCertificateSkipsNonCertificateBlocks verifies that a bundle carrying a private
// key alongside the root is still usable.
//
// Bundles are routinely concatenated by hand, so a stray non-certificate block must be
// stepped over rather than treated as the end of the bundle.
func TestVerifyCertificateSkipsNonCertificateBlocks(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	now := time.Now().UTC()
	cert := testFixtureCert(t, "user-root.crt")

	// The root which issued the certificate, preceded by a block which is not a certificate
	bundle := append(
		testFixtureBytes(t, "self-signed.key"), testFixtureBytes(t, "root-ca.crt")...,
	)

	assert.Nil(verifyCertificate(cert, bundle, now))
}
