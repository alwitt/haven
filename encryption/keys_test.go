package encryption_test

import (
	"context"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	mockdb "github.com/alwitt/haven/mocks/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCryptoEngineNewKey(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// RSA cert files
	testCertFile, err := filepath.Abs("../test/certs/self-signed.crt")
	assert.Nil(err)
	testKeyFile, err := filepath.Abs("../test/certs/self-signed.key")
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
		mock.AnythingOfType("string"),
	).Run(func(args mock.Arguments) {
		encKey, ok := args.Get(1).([]byte)
		assert.True(ok)
		testKey1.EncKeyMaterial = encKey
	}).Return(testKey1, nil).Once()
	// Record "new" key
	newKey, err := uut1.NewEncryptionKey(utCtx, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey1.ID, newKey.ID)

	// Read test key 1 back using different instance
	uut2, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
		Persistence:        mockDBClient,
		PrimaryRSACertFile: testCertFile,
		PrimaryRSAKeyFile:  testKeyFile,
	})
	assert.Nil(err)
	mockDatabase.On(
		"GetEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey1.ID,
	).Return(testKey1, nil).Once()
	readKey, err := uut2.GetEncryptionKey(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey1.ID, readKey.ID)
}

func TestCryptoEngineListKeys(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// RSA cert files
	testCertFile, err := filepath.Abs("../test/certs/self-signed.crt")
	assert.Nil(err)
	testKeyFile, err := filepath.Abs("../test/certs/self-signed.key")
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
		mock.AnythingOfType("string"),
	).Run(func(args mock.Arguments) {
		encKey, ok := args.Get(1).([]byte)
		assert.True(ok)
		testKey1.EncKeyMaterial = encKey
	}).Return(testKey1, nil).Once()
	// Record "new" key
	newKey, err := uut1.NewEncryptionKey(utCtx, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey1.ID, newKey.ID)

	// Define test key 2
	testKey2 := models.EncryptionKey{
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
		testKey2.EncKeyMaterial = encKey
	}).Return(testKey2, nil).Once()
	// Record "new" key
	newKey, err = uut1.NewEncryptionKey(utCtx, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey2.ID, newKey.ID)

	// List keys
	mockDatabase.On(
		"ListEncryptionKeys",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.AnythingOfType("db.EncryptionKeyQueryFilter"),
	).Return([]models.EncryptionKey{testKey1, testKey2}, nil).Once()
	knownKeys, err := uut1.ListEncryptionKeys(utCtx, db.EncryptionKeyQueryFilter{}, mockDatabase)
	assert.Nil(err)
	assert.Len(knownKeys, 2)
	assert.Equal(testKey1.ID, knownKeys[0].ID)
	assert.Equal(testKey2.ID, knownKeys[1].ID)
}

func TestCryptoEngineKeyCacheExpiry(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// RSA cert files
	testCertFile, err := filepath.Abs("../test/certs/self-signed.crt")
	assert.Nil(err)
	testKeyFile, err := filepath.Abs("../test/certs/self-signed.key")
	assert.Nil(err)

	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)

	cacheTTL := time.Millisecond * 20

	uut1, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
		Persistence:        mockDBClient,
		PrimaryRSACertFile: testCertFile,
		PrimaryRSAKeyFile:  testKeyFile,
		KeyCacheTTL:        cacheTTL,
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
		mock.AnythingOfType("string"),
	).Run(func(args mock.Arguments) {
		encKey, ok := args.Get(1).([]byte)
		assert.True(ok)
		testKey1.EncKeyMaterial = encKey
	}).Return(testKey1, nil).Once()
	// Record "new" key
	newKey, err := uut1.NewEncryptionKey(utCtx, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey1.ID, newKey.ID)

	// Within TTL: served from cache, no persistence read
	readKey, err := uut1.GetEncryptionKey(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey1.ID, readKey.ID)

	// After TTL: re-validated against persistence, key still active
	time.Sleep(cacheTTL * 3)
	activeTestKey1 := models.EncryptionKey{
		ID:             testKey1.ID,
		State:          models.EncryptionKeyStateActive,
		EncKeyMaterial: testKey1.EncKeyMaterial,
	}
	mockDatabase.On(
		"GetEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey1.ID,
	).Return(activeTestKey1, nil).Once()
	readKey, err = uut1.GetEncryptionKey(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(activeTestKey1, readKey)

	// Fresh again: served from cache
	readKey, err = uut1.GetEncryptionKey(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(activeTestKey1, readKey)

	// After TTL: persistence now reports the key retired by a maintenance action
	time.Sleep(cacheTTL * 3)
	retiredTestKey1 := models.EncryptionKey{
		ID:             testKey1.ID,
		State:          models.EncryptionKeyStateRetired,
		EncKeyMaterial: testKey1.EncKeyMaterial,
	}
	mockDatabase.On(
		"GetEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey1.ID,
	).Return(retiredTestKey1, nil).Once()
	readKey, err = uut1.GetEncryptionKey(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(retiredTestKey1, readKey)

	// A retired key is cached like any other, so this read needs no persistence round trip
	readKey, err = uut1.GetEncryptionKey(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(retiredTestKey1, readKey)

	// It still never encrypts
	_, _, err = uut1.EncryptData(utCtx, testKey1.ID, []byte("hello world"), nil, mockDatabase)
	assert.Error(err)
}

// TestCryptoEngineRetiredKeyStaysCached verifies that a key retired by a maintenance
// action stays in the engine's cache and keeps decrypting, while refusing to encrypt.
//
// This is what an encryption key rotation runs on: it decrypts under the retired key for
// every version it moves, so evicting the key would cost an RSA unwrap per row.
//
// Key state is no longer changed through the engine; a maintenance action drives it
// through the persistence layer, and the engine notices on its next read.
func TestCryptoEngineRetiredKeyStaysCached(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// RSA cert files
	testCertFile, err := filepath.Abs("../test/certs/self-signed.crt")
	assert.Nil(err)
	testKeyFile, err := filepath.Abs("../test/certs/self-signed.key")
	assert.Nil(err)

	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)

	uut1, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
		Persistence:        mockDBClient,
		PrimaryRSACertFile: testCertFile,
		PrimaryRSAKeyFile:  testKeyFile,
		KeyCacheTTL:        time.Hour,
	})
	assert.Nil(err)

	testKey1 := models.EncryptionKey{
		ID:    uuid.NewString(),
		State: models.EncryptionKeyStateActive,
	}
	mockDatabase.On(
		"RecordEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.AnythingOfType("[]uint8"),
		mock.AnythingOfType("string"),
	).Run(func(args mock.Arguments) {
		encKey, ok := args.Get(1).([]byte)
		assert.True(ok)
		testKey1.EncKeyMaterial = encKey
	}).Return(testKey1, nil).Once()
	newKey, err := uut1.NewEncryptionKey(utCtx, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey1.ID, newKey.ID)

	// Inside the TTL the key is served from cache, without touching persistence
	readKey, err := uut1.GetEncryptionKey(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(testKey1.ID, readKey.ID)

	// Seal something under the key while it is still active
	_, encrypted, err := uut1.EncryptData(
		utCtx, testKey1.ID, []byte("hello world"), []byte("aad"), mockDatabase,
	)
	assert.Nil(err)

	// A listing carrying the retired key refreshes the cache, which keeps it
	retiredTestKey1 := models.EncryptionKey{
		ID:             testKey1.ID,
		State:          models.EncryptionKeyStateRetired,
		EncKeyMaterial: testKey1.EncKeyMaterial,
	}
	mockDatabase.On(
		"ListEncryptionKeys",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.AnythingOfType("db.EncryptionKeyQueryFilter"),
	).Return([]models.EncryptionKey{retiredTestKey1}, nil).Once()
	listed, err := uut1.ListEncryptionKeys(utCtx, db.EncryptionKeyQueryFilter{}, mockDatabase)
	assert.Nil(err)
	assert.Len(listed, 1)

	// The new state is visible, and served from cache without a persistence round trip
	readKey, err = uut1.GetEncryptionKey(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(models.EncryptionKeyStateRetired, readKey.State)

	// A retired key still decrypts: this is what a rotation reads its data through
	_, plainText, err := uut1.DecryptData(utCtx, testKey1.ID, encrypted, []byte("aad"), mockDatabase)
	assert.Nil(err)
	assert.Equal([]byte("hello world"), plainText)

	// A retired key never encrypts
	_, _, err = uut1.EncryptData(utCtx, testKey1.ID, []byte("hello world"), nil, mockDatabase)
	assert.Error(err)
}

// TestCryptoEngineKEKIDStamping verifies that every key the engine mints is stamped with
// an ID identifying the primary RSA key pair which wrapped it.
func TestCryptoEngineKEKIDStamping(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// Mint one key through an engine built on a particular key pair, and report the KEK ID
	// the engine stamped onto it
	kekIDFor := func(fixture string) string {
		testCertFile, err := filepath.Abs("../test/certs/" + fixture + ".crt")
		assert.Nil(err)
		testKeyFile, err := filepath.Abs("../test/certs/" + fixture + ".key")
		assert.Nil(err)

		mockDBClient := mockdb.NewClient(t)
		mockDatabase := mockdb.NewDatabase(t)

		uut, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
			Persistence:        mockDBClient,
			PrimaryRSACertFile: testCertFile,
			PrimaryRSAKeyFile:  testKeyFile,
			KeyCacheTTL:        time.Hour,
		})
		assert.Nil(err)

		testKey := models.EncryptionKey{ID: uuid.NewString(), State: models.EncryptionKeyStateActive}
		var observed string
		mockDatabase.On(
			"RecordEncryptionKey",
			mock.AnythingOfType("context.backgroundCtx"),
			mock.AnythingOfType("[]uint8"),
			mock.AnythingOfType("string"),
		).Run(func(args mock.Arguments) {
			kekID, ok := args.Get(2).(string)
			assert.True(ok)
			observed = kekID
		}).Return(testKey, nil).Once()

		_, err = uut.NewEncryptionKey(utCtx, mockDatabase)
		assert.Nil(err)

		return observed
	}

	selfSigned := kekIDFor("self-signed")

	// A SHA-256 digest, hex encoded
	assert.Len(selfSigned, 64)
	_, err := hex.DecodeString(selfSigned)
	assert.Nil(err)

	// Stable for a given key pair, so it survives certificate renewal
	assert.Equal(selfSigned, kekIDFor("self-signed"))

	// And distinct for a different key pair, so a mismatch is detectable
	assert.NotEqual(selfSigned, kekIDFor("user-root"))
}
