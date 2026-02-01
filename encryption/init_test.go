package encryption_test

import (
	"context"
	"path/filepath"
	"testing"

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
	testCertFile, err := filepath.Abs("../test/ut_rsa.crt")
	assert.Nil(err)
	testKeyFile, err := filepath.Abs("../test/ut_rsa.key")
	assert.Nil(err)

	// Case 1: with RSA cert file
	{
		_, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
			PrimaryRSACertFile: testCertFile,
			PrimaryRSAKeyFile:  testKeyFile,
		})
		assert.Nil(err)
	}
}
