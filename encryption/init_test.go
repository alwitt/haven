package encryption_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/alwitt/haven/encryption"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestCryptoEngineInit(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// Case 0: no RSA files
	{
		_, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{})
		assert.Error(err)
	}

	// RSA cert files
	testCertFile, err := filepath.Abs("../test/certs/self-signed.crt")
	assert.Nil(err)
	testKeyFile, err := filepath.Abs("../test/certs/self-signed.key")
	assert.Nil(err)

	// Case 1: with RSA cert file
	{
		_, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
			PrimaryRSACertFile: testCertFile,
			PrimaryRSAKeyFile:  testKeyFile,
		})
		assert.Nil(err)
	}

	// Case 2: negative key cache TTL
	{
		_, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
			PrimaryRSACertFile: testCertFile,
			PrimaryRSAKeyFile:  testKeyFile,
			KeyCacheTTL:        -time.Second,
		})
		assert.Error(err)
	}
}

// TestCryptoEngineInitCertValidation exercises the certificate checks in LoadKEK, as the
// engine's own key pair passes through them at construction, against the fixtures produced
// by test/gen_certs.py
func TestCryptoEngineInitCertValidation(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	fixture := func(name string) string {
		path, err := filepath.Abs(filepath.Join("../test/certs", name))
		assert.Nil(err)
		return path
	}
	caChain := fixture("ca-chain.crt")
	rootOnly := fixture("root-ca.crt")
	intermediateOnly := fixture("intermediate-ca.crt")
	missing := fixture("does-not-exist.crt")

	for _, entry := range []struct {
		name       string
		certFile   string
		keyFile    string
		caCertFile *string
		wantErr    string
	}{
		{
			name:     "self-signed, no chain",
			certFile: fixture("self-signed.crt"), keyFile: fixture("self-signed.key"),
		},
		{
			name:     "signed by root, chain",
			certFile: fixture("user-root.crt"), keyFile: fixture("user-root.key"),
			caCertFile: &caChain,
		},
		{
			name:     "signed by intermediate, chain",
			certFile: fixture("user-intermediate.crt"), keyFile: fixture("user-intermediate.key"),
			caCertFile: &caChain,
		},
		{
			name:     "signed by intermediate, bundle missing the intermediate",
			certFile: fixture("user-intermediate.crt"), keyFile: fixture("user-intermediate.key"),
			caCertFile: &rootOnly,
			wantErr:    "does not chain",
		},
		{
			name:     "signed by intermediate, bundle missing the root",
			certFile: fixture("user-intermediate.crt"), keyFile: fixture("user-intermediate.key"),
			caCertFile: &intermediateOnly,
			wantErr:    "no self-signed root",
		},
		{
			name:     "expired, no chain",
			certFile: fixture("user-expired.crt"), keyFile: fixture("user-expired.key"),
			wantErr: "expired on",
		},
		{
			name:     "expired, chain",
			certFile: fixture("user-expired.crt"), keyFile: fixture("user-expired.key"),
			caCertFile: &caChain,
			wantErr:    "expired on",
		},
		{
			name:     "self-signed, unrelated chain",
			certFile: fixture("self-signed.crt"), keyFile: fixture("self-signed.key"),
			caCertFile: &caChain,
			wantErr:    "does not chain",
		},
		{
			name:     "key does not match certificate",
			certFile: fixture("user-root.crt"), keyFile: fixture("user-intermediate.key"),
			wantErr: "does not match",
		},
		{
			name:     "chain file does not exist",
			certFile: fixture("self-signed.crt"), keyFile: fixture("self-signed.key"),
			caCertFile: &missing,
			wantErr:    "invalid engine init parameters",
		},
	} {
		_, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
			PrimaryRSACertFile:   entry.certFile,
			PrimaryRSAKeyFile:    entry.keyFile,
			PrimaryRSACACertFile: entry.caCertFile,
		})
		if entry.wantErr == "" {
			assert.Nil(err, entry.name)
		} else {
			assert.ErrorContains(err, entry.wantErr, entry.name)
		}
	}
}
