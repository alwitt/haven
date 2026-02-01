package encryption_test

import (
	"context"
	"path/filepath"
	"testing"

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

func TestCryptoEngineChangeKeyState(t *testing.T) {
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

	// Deactivate key
	inactiveTestKey1 := models.EncryptionKey{
		ID:    uuid.NewString(),
		State: models.EncryptionKeyStateInactive,
	}
	mockDatabase.On(
		"MarkEncryptionKeyInactive",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey1.ID,
	).Return(nil).Once()
	mockDatabase.On(
		"GetEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey1.ID,
	).Return(inactiveTestKey1, nil).Once()
	theKey, err := uut1.MarkEncryptionKeyInactive(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(inactiveTestKey1, theKey)

	// Activate key
	activeTestKey1 := models.EncryptionKey{
		ID:             uuid.NewString(),
		State:          models.EncryptionKeyStateActive,
		EncKeyMaterial: testKey1.EncKeyMaterial,
	}
	mockDatabase.On(
		"MarkEncryptionKeyActive",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey1.ID,
	).Return(nil).Once()
	mockDatabase.On(
		"GetEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey1.ID,
	).Return(activeTestKey1, nil).Once()
	theKey, err = uut1.MarkEncryptionKeyActive(utCtx, testKey1.ID, mockDatabase)
	assert.Nil(err)
	assert.Equal(activeTestKey1, theKey)
}

func TestCryptoEngineDeleteKey(t *testing.T) {
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

	// Delete key
	mockDatabase.On(
		"DeleteEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey1.ID,
	).Return(nil).Once()
	assert.Nil(uut1.DeleteEncryptionKey(utCtx, testKey1.ID, mockDatabase))
}
