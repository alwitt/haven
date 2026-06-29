package encryption

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/models"
)

// loadRSAKeyPair load the primary RSA key pair for encrypting and decrypting symmetric keys
func (e *cryptoEngine) loadRSAKeyPair(
	ctx context.Context, certFilePath string, keyFilePath string,
) error {
	certFile, err := os.Open(certFilePath)
	if err != nil {
		return goutils.NewRuntimeError(fmt.Sprintf("failed to open %s", certFilePath), err, true)
	}

	keyFile, err := os.Open(keyFilePath)
	if err != nil {
		return goutils.NewRuntimeError(fmt.Sprintf("failed to open %s", keyFilePath), err, true)
	}

	certContent, err := io.ReadAll(certFile)
	if err != nil {
		return goutils.NewRuntimeError(fmt.Sprintf("%s read error", certFilePath), err, true)
	}

	keyContent, err := io.ReadAll(keyFile)
	if err != nil {
		return goutils.NewRuntimeError(fmt.Sprintf("%s read error", keyFilePath), err, true)
	}

	parsedCert, err := e.crypto.ParseCertificateFromPEM(ctx, string(certContent))
	if err != nil {
		return models.NewEncryptionError(
			fmt.Sprintf("failed to parse x509 certificate in %s", certFilePath), err, true,
		)
	}

	parsedKey, err := e.crypto.ParseRSAPrivateKeyFromPEM(ctx, string(keyContent))
	if err != nil {
		return models.NewEncryptionError(
			fmt.Sprintf("failed to parse RSA private key in %s", keyFilePath), err, true,
		)
	}

	parsedPubKey, err := e.crypto.ReadRSAPublicKeyFromCert(ctx, parsedCert)
	if err != nil {
		return models.NewEncryptionError(
			fmt.Sprintf("failed to pull RSA public key from x509 certificate in %s", certFilePath),
			err, true,
		)
	}

	e.rsaKey = parsedKey
	e.rsaPubKey = parsedPubKey

	return nil
}
