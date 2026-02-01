package encryption

import (
	"context"
	"fmt"
	"io"
	"os"
)

// loadRSAKeyPair load the primary RSA key pair for encrypting and decrypting symmetric keys
func (e *cryptoEngine) loadRSAKeyPair(
	ctx context.Context, certFilePath string, keyFilePath string,
) error {
	certFile, err := os.Open(certFilePath)
	if err != nil {
		return fmt.Errorf("failed to open %s [%w]", certFilePath, err)
	}

	keyFile, err := os.Open(keyFilePath)
	if err != nil {
		return fmt.Errorf("failed to open %s [%w]", keyFilePath, err)
	}

	certContent, err := io.ReadAll(certFile)
	if err != nil {
		return fmt.Errorf("%s read error [%w]", certFilePath, err)
	}

	keyContent, err := io.ReadAll(keyFile)
	if err != nil {
		return fmt.Errorf("%s read error [%w]", keyFilePath, err)
	}

	parsedCert, err := e.crypto.ParseCertificateFromPEM(ctx, string(certContent))
	if err != nil {
		return fmt.Errorf("failed to parse x509 certificate in %s [%w]", certFilePath, err)
	}

	parsedKey, err := e.crypto.ParseRSAPrivateKeyFromPEM(ctx, string(keyContent))
	if err != nil {
		return fmt.Errorf("failed to parse RSA private key in %s [%w]", keyFilePath, err)
	}

	parsedPubKey, err := e.crypto.ReadRSAPublicKeyFromCert(ctx, parsedCert)
	if err != nil {
		return fmt.Errorf(
			"failed to pull RSA public key from x509 certificate in %s [%w]", certFilePath, err,
		)
	}

	e.rsaKey = parsedKey
	e.rsaPubKey = parsedPubKey

	return nil
}
