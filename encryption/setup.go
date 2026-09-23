package encryption

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/models"
)

/*
KEKID the ID of the primary RSA key pair this engine is configured with

	@returns the key pair ID
*/
func (e *cryptoEngine) KEKID() string {
	return e.kek.ID()
}

/*
LoadKEK load a primary RSA key pair without adopting it

The certificate must be within its validity window, and must belong to the private key.
When a CA bundle is given, the certificate must also chain to a root in that bundle. These
are the same checks the engine's own key pair passes at construction.

	@param ctx context.Context - execution context
	@param params KEKParams - the key pair file paths
	@returns the loaded key pair
*/
func (e *cryptoEngine) LoadKEK(ctx context.Context, params KEKParams) (KEK, error) {
	if err := e.validator.Struct(&params); err != nil {
		return KEK{}, goutils.NewValidationError("invalid RSA key pair parameters", err, true)
	}

	certContent, err := os.ReadFile(params.CertFile)
	if err != nil {
		return KEK{}, goutils.NewRuntimeError(
			fmt.Sprintf("failed to read %s", params.CertFile), err, true,
		)
	}

	keyContent, err := os.ReadFile(params.KeyFile)
	if err != nil {
		return KEK{}, goutils.NewRuntimeError(
			fmt.Sprintf("failed to read %s", params.KeyFile), err, true,
		)
	}

	var caBundle []byte
	if params.CACertFile != nil {
		caBundle, err = os.ReadFile(*params.CACertFile)
		if err != nil {
			return KEK{}, goutils.NewRuntimeError(
				fmt.Sprintf("failed to read %s", *params.CACertFile), err, true,
			)
		}
	}

	parsedCert, err := e.crypto.ParseCertificateFromPEM(ctx, string(certContent))
	if err != nil {
		return KEK{}, models.NewEncryptionError(
			fmt.Sprintf("failed to parse x509 certificate in %s", params.CertFile), err, true,
		)
	}

	parsedKey, err := e.crypto.ParseRSAPrivateKeyFromPEM(ctx, string(keyContent))
	if err != nil {
		return KEK{}, models.NewEncryptionError(
			fmt.Sprintf("failed to parse RSA private key in %s", params.KeyFile), err, true,
		)
	}

	if err := verifyCertificate(parsedCert, caBundle, time.Now().UTC()); err != nil {
		return KEK{}, models.NewEncryptionError(
			fmt.Sprintf("x509 certificate in %s rejected", params.CertFile), err, true,
		)
	}

	parsedPubKey, err := e.crypto.ReadRSAPublicKeyFromCert(ctx, parsedCert)
	if err != nil {
		return KEK{}, models.NewEncryptionError(
			fmt.Sprintf(
				"failed to pull RSA public key from x509 certificate in %s", params.CertFile,
			),
			err, true,
		)
	}

	if !parsedKey.PublicKey.Equal(parsedPubKey) {
		return KEK{}, models.NewEncryptionError(
			fmt.Sprintf(
				"RSA private key in %s does not match x509 certificate in %s",
				params.KeyFile, params.CertFile,
			),
			nil, true,
		)
	}

	kekID, err := kekIDOf(parsedPubKey)
	if err != nil {
		return KEK{}, models.NewEncryptionError(
			fmt.Sprintf(
				"failed to derive the key ID of the RSA public key in %s", params.CertFile,
			),
			err, true,
		)
	}

	return KEK{privateKey: parsedKey, publicKey: parsedPubKey, id: kekID}, nil
}

// kekIDOf derive the ID identifying a primary RSA key pair
//
// The ID is the hex SHA-256 of the public key's SPKI DER. Being a property of the key
// rather than of the certificate carrying it, it survives certificate renewal and changes
// only when the key pair itself does.
func kekIDOf(pubKey *rsa.PublicKey) (string, error) {
	spki, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", goutils.NewRuntimeError("failed to serialize RSA public key", err, true)
	}
	digest := sha256.Sum256(spki)
	return hex.EncodeToString(digest[:]), nil
}

// verifyCertificate check a certificate is valid at `now`, and chains to a root in the CA
// bundle when one is given
//
// Self-signed certificates in the bundle are trust anchors; all others are intermediates a
// chain may pass through. Revocation is not checked.
func verifyCertificate(cert *x509.Certificate, caBundle []byte, now time.Time) error {
	// Checked explicitly so the failure reads the same with or without a bundle
	if now.Before(cert.NotBefore) {
		return goutils.NewValidationError(
			fmt.Sprintf("certificate not valid until %s", cert.NotBefore.UTC()), nil, true,
		)
	}
	if now.After(cert.NotAfter) {
		return goutils.NewValidationError(
			fmt.Sprintf("certificate expired on %s", cert.NotAfter.UTC()), nil, true,
		)
	}

	// Skipping trust chain verification as no trust store provided
	if caBundle == nil {
		return nil
	}

	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	certCount, rootCount := 0, 0
	for rest := caBundle; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return goutils.NewValidationError(
				fmt.Sprintf("failed to parse CA bundle certificate %d", certCount), err, true,
			)
		}
		certCount++
		if caCert.CheckSignatureFrom(caCert) == nil {
			roots.AddCert(caCert)
			rootCount++
		} else {
			intermediates.AddCert(caCert)
		}
	}
	if certCount == 0 {
		return goutils.NewValidationError("CA bundle contains no certificates", nil, true)
	}
	if rootCount == 0 {
		return goutils.NewValidationError("CA bundle contains no self-signed root", nil, true)
	}

	// An empty KeyUsages defaults to server auth, which a key encryption cert need not carry
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return goutils.NewValidationError("certificate does not chain to CA bundle", err, true)
	}

	return nil
}
