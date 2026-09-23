package encryption_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

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
	testCertFile, err := filepath.Abs("../test/certs/self-signed.crt")
	assert.Nil(err)
	testKeyFile, err := filepath.Abs("../test/certs/self-signed.key")
	assert.Nil(err)

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

	// Case 0: key cache in effect, the key is never re-read from persistence
	{
		mockDBClient := mockdb.NewClient(t)
		mockDatabase := mockdb.NewDatabase(t)

		uut, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
			Persistence:        mockDBClient,
			PrimaryRSACertFile: testCertFile,
			PrimaryRSAKeyFile:  testKeyFile,
			KeyCacheTTL:        time.Hour,
		})
		assert.Nil(err)

		// Define test key
		testKey := models.EncryptionKey{
			ID:    uuid.NewString(),
			State: models.EncryptionKeyStateActive,
		}
		// Setup mock
		mockDatabase.On(
			"RecordEncryptionKey",
			mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("[]uint8"),
			mock.AnythingOfType("string"),
		).Run(func(args mock.Arguments) {
			encKey, ok := args.Get(1).([]byte)
			assert.True(ok)
			testKey.EncKeyMaterial = encKey
		}).Return(testKey, nil).Once()
		// Record "new" key
		newKey, err := uut.NewEncryptionKey(utCtx, mockDatabase)
		assert.Nil(err)
		assert.Equal(testKey.ID, newKey.ID)

		// Perform encryption
		encKey, cipherText, err := uut.EncryptData(utCtx, testKey.ID, plainText, nil, mockDatabase)
		assert.Nil(err)
		assert.Equal(testKey.ID, encKey.ID)

		// Perform decryption
		encKey, decrypted, err := uut.DecryptData(utCtx, testKey.ID, cipherText, nil, mockDatabase)
		assert.Nil(err)
		assert.Equal(testKey.ID, encKey.ID)
		assert.Equal(plainText, decrypted)
	}

	// Case 1: zero TTL, the key is re-validated against persistence on every use
	{
		mockDBClient := mockdb.NewClient(t)
		mockDatabase := mockdb.NewDatabase(t)

		uut, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
			Persistence:        mockDBClient,
			PrimaryRSACertFile: testCertFile,
			PrimaryRSAKeyFile:  testKeyFile,
			KeyCacheTTL:        0,
		})
		assert.Nil(err)

		// Define test key
		testKey := models.EncryptionKey{
			ID:    uuid.NewString(),
			State: models.EncryptionKeyStateActive,
		}
		// Setup mock
		mockDatabase.On(
			"RecordEncryptionKey",
			mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("[]uint8"),
			mock.AnythingOfType("string"),
		).Run(func(args mock.Arguments) {
			encKey, ok := args.Get(1).([]byte)
			assert.True(ok)
			testKey.EncKeyMaterial = encKey
		}).Return(testKey, nil).Once()
		// Record "new" key
		newKey, err := uut.NewEncryptionKey(utCtx, mockDatabase)
		assert.Nil(err)
		assert.Equal(testKey.ID, newKey.ID)

		// Perform encryption
		mockDatabase.On(
			"GetEncryptionKey",
			mock.AnythingOfType("context.backgroundCtx"),
			testKey.ID,
		).Return(testKey, nil).Times(2)
		encKey, cipherText, err := uut.EncryptData(utCtx, testKey.ID, plainText, nil, mockDatabase)
		assert.Nil(err)
		assert.Equal(testKey.ID, encKey.ID)

		// Perform decryption
		encKey, decrypted, err := uut.DecryptData(utCtx, testKey.ID, cipherText, nil, mockDatabase)
		assert.Nil(err)
		assert.Equal(testKey.ID, encKey.ID)
		assert.Equal(plainText, decrypted)
	}

	// Case 2: associated data must match to decrypt
	{
		mockDBClient := mockdb.NewClient(t)
		mockDatabase := mockdb.NewDatabase(t)

		uut, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
			Persistence:        mockDBClient,
			PrimaryRSACertFile: testCertFile,
			PrimaryRSAKeyFile:  testKeyFile,
			KeyCacheTTL:        time.Hour,
		})
		assert.Nil(err)

		// Define test key
		testKey := models.EncryptionKey{
			ID:    uuid.NewString(),
			State: models.EncryptionKeyStateActive,
		}
		// Setup mock
		mockDatabase.On(
			"RecordEncryptionKey",
			mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("[]uint8"),
			mock.AnythingOfType("string"),
		).Run(func(args mock.Arguments) {
			encKey, ok := args.Get(1).([]byte)
			assert.True(ok)
			testKey.EncKeyMaterial = encKey
		}).Return(testKey, nil).Once()
		// Record "new" key
		newKey, err := uut.NewEncryptionKey(utCtx, mockDatabase)
		assert.Nil(err)
		assert.Equal(testKey.ID, newKey.ID)

		additional := []byte(uuid.NewString())

		// Encrypt with associated data
		_, cipherText, err := uut.EncryptData(utCtx, testKey.ID, plainText, additional, mockDatabase)
		assert.Nil(err)

		// Matching associated data decrypts
		_, decrypted, err := uut.DecryptData(utCtx, testKey.ID, cipherText, additional, mockDatabase)
		assert.Nil(err)
		assert.Equal(plainText, decrypted)

		// Different associated data fails
		_, _, err = uut.DecryptData(
			utCtx, testKey.ID, cipherText, []byte(uuid.NewString()), mockDatabase,
		)
		assert.Error(err)

		// Missing associated data fails
		_, _, err = uut.DecryptData(utCtx, testKey.ID, cipherText, nil, mockDatabase)
		assert.Error(err)

		// Empty associated data is treated as missing, and does not panic
		_, _, err = uut.DecryptData(utCtx, testKey.ID, cipherText, []byte{}, mockDatabase)
		assert.Error(err)
	}

	// Case 3: payloads the AEAD cannot process are refused instead of panicking
	{
		mockDBClient := mockdb.NewClient(t)
		mockDatabase := mockdb.NewDatabase(t)

		uut, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
			Persistence:        mockDBClient,
			PrimaryRSACertFile: testCertFile,
			PrimaryRSAKeyFile:  testKeyFile,
			KeyCacheTTL:        time.Hour,
		})
		assert.Nil(err)

		// Define test key
		testKey := models.EncryptionKey{
			ID:    uuid.NewString(),
			State: models.EncryptionKeyStateActive,
		}
		// Setup mock
		mockDatabase.On(
			"RecordEncryptionKey",
			mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("[]uint8"),
			mock.AnythingOfType("string"),
		).Run(func(args mock.Arguments) {
			encKey, ok := args.Get(1).([]byte)
			assert.True(ok)
			testKey.EncKeyMaterial = encKey
		}).Return(testKey, nil).Once()
		// Record "new" key
		_, err = uut.NewEncryptionKey(utCtx, mockDatabase)
		assert.Nil(err)

		// A valid cipher text carries the 16 byte tag on top of the plain text
		_, cipherText, err := uut.EncryptData(utCtx, testKey.ID, plainText, nil, mockDatabase)
		assert.Nil(err)
		assert.Len(cipherText.CipherText, len(plainText)+16)

		// Empty plain text
		for _, empty := range [][]byte{nil, {}} {
			_, _, err := uut.EncryptData(utCtx, testKey.ID, empty, nil, mockDatabase)
			assert.ErrorContains(err, "plain text is empty")
		}

		// Cipher text shorter than, or exactly, the tag
		for _, short := range []int{0, 15, 16} {
			_, _, err := uut.DecryptData(utCtx, testKey.ID, encryption.EncryptedData{
				CipherText: cipherText.CipherText[:short], Nonce: cipherText.Nonce,
			}, nil, mockDatabase)
			assert.ErrorContains(err, "cipher text too short", "length %d", short)
		}

		// One byte beyond the tag reaches the AEAD, which rejects the truncated payload
		_, _, err = uut.DecryptData(utCtx, testKey.ID, encryption.EncryptedData{
			CipherText: cipherText.CipherText[:17], Nonce: cipherText.Nonce,
		}, nil, mockDatabase)
		assert.Error(err)
		assert.NotContains(err.Error(), "cipher text too short")
	}
}
