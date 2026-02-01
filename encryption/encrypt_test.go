package encryption_test

import (
	"context"
	"path/filepath"
	"testing"

	cgoCrypto "github.com/alwitt/cgoutils/crypto"
	"github.com/alwitt/haven/encryption"
	mockdb "github.com/alwitt/haven/mocks/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCryptoEngineEncryptData(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// RSA cert files
	testCertFile, err := filepath.Abs("../test/ut_rsa.crt")
	assert.Nil(err)
	testKeyFile, err := filepath.Abs("../test/ut_rsa.key")
	assert.Nil(err)

	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)

	uut1, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
		Persistence:        mockDBClient,
		PrimaryRSACertFile: testCertFile,
		PrimaryRSAKeyFile:  testKeyFile,
	})
	assert.Nil(err)

	// Define test key 1
	testKey1 := models.EncryptionKey{
		ID:    uuid.NewString(),
		State: models.EncryptionKeyStateActive,
	}
	// Setup mock
	mockDatabase.On(
		"RecordEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.AnythingOfType("[]uint8"),
	).Run(func(args mock.Arguments) {
		encKey, ok := args.Get(1).([]byte)
		assert.True(ok)
		testKey1.EncKeyMaterial = encKey
	}).Return(testKey1, nil).Once()
	// Record "new" key
	newKey, err := uut1.NewEncryptionKey(utCtx, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey1.ID, newKey.ID)

	plainText := make([]byte, 1024)
	{
		coreCrypto, err := cgoCrypto.NewEngine(log.Fields{
			"package": "cgoutils", "module": "crypto", "component": "crypto-engine",
		})
		assert.Nil(err)
		rng := coreCrypto.GetRNGReader()
		read, err := rng.Read(plainText)
		assert.Nil(err)
		assert.Equal(len(plainText), read)
	}

	// Perform encryption
	mockDatabase.On(
		"GetEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey1.ID,
	).Return(testKey1, nil).Times(2)
	encKey, cipherText, err := uut1.EncryptData(utCtx, testKey1.ID, plainText, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey1.ID, encKey.ID)

	// Perform decryption
	encKey, decrypted, err := uut1.DecryptData(utCtx, testKey1.ID, cipherText, mockDatabase)
	assert.Nil(err)
	assert.Equal(plainText, decrypted)
}
