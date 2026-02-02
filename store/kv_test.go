package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	mockdb "github.com/alwitt/haven/mocks/db"
	mockencryption "github.com/alwitt/haven/mocks/encryption"
	"github.com/alwitt/haven/models"
	"github.com/alwitt/haven/store"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestKVStoreInit(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)
	mockCrypto := mockencryption.NewCryptographyEngine(t)
	// Return the mock DB
	mockDBClient.On(
		"UseDatabaseInTransaction",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.Anything,
	).Run(func(args mock.Arguments) {
		callBack, ok := args.Get(1).(func(ctx context.Context, dbClient db.Database) error)
		assert.True(ok)
		assert.Nil(callBack(utCtx, mockDatabase))
	}).Return(nil).Maybe()

	testEncKey := models.EncryptionKey{ID: uuid.NewString()}

	mockCrypto.On(
		"ListEncryptionKeys",
		mock.AnythingOfType("context.backgroundCtx"),
		db.EncryptionKeyQueryFilter{
			TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateActive},
		},
		mockDatabase,
	).Return(nil, nil).Once()
	mockCrypto.On(
		"NewEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		mockDatabase,
	).Return(testEncKey, nil)
	_, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
	assert.Nil(err)
}

func TestKVStoreRecordNewKey(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)
	mockCrypto := mockencryption.NewCryptographyEngine(t)
	// Return the mock DB
	mockDBClient.On(
		"UseDatabaseInTransaction",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.Anything,
	).Run(func(args mock.Arguments) {
		callBack, ok := args.Get(1).(func(ctx context.Context, dbClient db.Database) error)
		assert.True(ok)
		assert.Nil(callBack(utCtx, mockDatabase))
	}).Return(nil).Maybe()

	testEncKey := models.EncryptionKey{ID: uuid.NewString()}

	mockCrypto.On(
		"ListEncryptionKeys",
		mock.AnythingOfType("context.backgroundCtx"),
		db.EncryptionKeyQueryFilter{
			TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateActive},
		},
		mockDatabase,
	).Return(nil, nil).Once()
	mockCrypto.On(
		"NewEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		mockDatabase,
	).Return(testEncKey, nil)
	uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
	assert.Nil(err)

	testKey := uuid.NewString()
	testValue := uuid.NewString()
	testEncValue := uuid.NewString()
	testNonce := uuid.NewString()
	timestamp := time.Now().UTC()

	// Record a new uut and value
	testRecord := models.Record{ID: uuid.NewString()}
	testVersion := models.RecordVersion{ID: uuid.NewString()}
	mockDatabase.On(
		"GetRecordByName",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey,
	).Return(testRecord, nil).Once()
	mockCrypto.On(
		"EncryptData",
		mock.AnythingOfType("context.backgroundCtx"),
		testEncKey.ID,
		[]byte(testValue),
		mockDatabase,
	).Return(testEncKey, encryption.EncryptedData{
		CipherText: []byte(testEncValue), Nonce: []byte(testNonce),
	}, nil).Once()
	mockDatabase.On(
		"DefineNewVersionForRecord",
		mock.AnythingOfType("context.backgroundCtx"),
		testRecord,
		testEncKey,
		[]byte(testEncValue),
		[]byte(testNonce),
		timestamp,
	).Return(testVersion, nil).Once()
	theRecord, theVersion, err := uut.RecordKeyValue(
		utCtx, testKey, []byte(testValue), timestamp, mockDatabase,
	)
	assert.Nil(err)
	assert.Equal(testRecord, theRecord)
	assert.Equal(testVersion, theVersion)
}

func TestKVStoreListVersions(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)
	mockCrypto := mockencryption.NewCryptographyEngine(t)
	// Return the mock DB
	mockDBClient.On(
		"UseDatabaseInTransaction",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.Anything,
	).Run(func(args mock.Arguments) {
		callBack, ok := args.Get(1).(func(ctx context.Context, dbClient db.Database) error)
		assert.True(ok)
		assert.Nil(callBack(utCtx, mockDatabase))
	}).Return(nil).Maybe()

	testEncKey := models.EncryptionKey{ID: uuid.NewString()}

	mockCrypto.On(
		"ListEncryptionKeys",
		mock.AnythingOfType("context.backgroundCtx"),
		db.EncryptionKeyQueryFilter{
			TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateActive},
		},
		mockDatabase,
	).Return(nil, nil).Once()
	mockCrypto.On(
		"NewEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		mockDatabase,
	).Return(testEncKey, nil)
	uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
	assert.Nil(err)

	testKey := uuid.NewString()
	testRecord := models.Record{ID: uuid.NewString()}
	testVersions := []models.RecordVersion{
		{ID: uuid.NewString()}, {ID: uuid.NewString()}, {ID: uuid.NewString()},
	}

	mockDatabase.On(
		"GetRecordByName",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey,
	).Return(testRecord, nil).Once()
	mockDatabase.On(
		"ListVersionsOfOneRecord",
		mock.AnythingOfType("context.backgroundCtx"),
		testRecord,
		db.RecordVersionQueryFilter{},
	).Return(testVersions, nil).Once()
	theRecord, knownVersions, err := uut.ListKeyVersions(utCtx, testKey, mockDatabase)
	assert.Nil(err)
	assert.Equal(testRecord, theRecord)
	assert.Equal(testVersions, knownVersions)
}

func TestKVStoreGetValueOfVersion(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)
	mockCrypto := mockencryption.NewCryptographyEngine(t)
	// Return the mock DB
	mockDBClient.On(
		"UseDatabaseInTransaction",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.Anything,
	).Run(func(args mock.Arguments) {
		callBack, ok := args.Get(1).(func(ctx context.Context, dbClient db.Database) error)
		assert.True(ok)
		assert.Nil(callBack(utCtx, mockDatabase))
	}).Return(nil).Maybe()

	testEncKey := models.EncryptionKey{ID: uuid.NewString()}

	mockCrypto.On(
		"ListEncryptionKeys",
		mock.AnythingOfType("context.backgroundCtx"),
		db.EncryptionKeyQueryFilter{
			TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateActive},
		},
		mockDatabase,
	).Return(nil, nil).Once()
	mockCrypto.On(
		"NewEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		mockDatabase,
	).Return(testEncKey, nil)
	uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
	assert.Nil(err)

	testVersion := models.RecordVersion{
		ID:       uuid.NewString(),
		EncKeyID: uuid.NewString(),
		EncValue: []byte(uuid.NewString()),
		EncNonce: []byte(uuid.NewString()),
	}
	testPlainTest := []byte(uuid.NewString())

	// Case 0: by version ID
	{
		mockDatabase.On(
			"GetRecordVersion",
			mock.AnythingOfType("context.backgroundCtx"),
			testVersion.ID,
		).Return(testVersion, nil).Once()
		mockCrypto.On(
			"DecryptData",
			mock.AnythingOfType("context.backgroundCtx"),
			testVersion.EncKeyID,
			encryption.EncryptedData{
				CipherText: testVersion.EncValue, Nonce: testVersion.EncNonce,
			},
			mockDatabase,
		).Return(testEncKey, testPlainTest, nil).Once()

		decrypted, err := uut.GetValueOfKeyAtVersionID(utCtx, testVersion.ID, mockDatabase)
		assert.Nil(err)
		assert.Equal(testPlainTest, decrypted)
	}

	// Case 1: by version
	{
		mockCrypto.On(
			"DecryptData",
			mock.AnythingOfType("context.backgroundCtx"),
			testVersion.EncKeyID,
			encryption.EncryptedData{
				CipherText: testVersion.EncValue, Nonce: testVersion.EncNonce,
			},
			mockDatabase,
		).Return(testEncKey, testPlainTest, nil).Once()

		decrypted, err := uut.GetValueOfKeyAtVersion(utCtx, testVersion, mockDatabase)
		assert.Nil(err)
		assert.Equal(testPlainTest, decrypted)
	}
}

func TestKVStoreDeleteKey(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)
	mockCrypto := mockencryption.NewCryptographyEngine(t)
	// Return the mock DB
	mockDBClient.On(
		"UseDatabaseInTransaction",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.Anything,
	).Run(func(args mock.Arguments) {
		callBack, ok := args.Get(1).(func(ctx context.Context, dbClient db.Database) error)
		assert.True(ok)
		assert.Nil(callBack(utCtx, mockDatabase))
	}).Return(nil).Maybe()

	testEncKey := models.EncryptionKey{ID: uuid.NewString()}

	mockCrypto.On(
		"ListEncryptionKeys",
		mock.AnythingOfType("context.backgroundCtx"),
		db.EncryptionKeyQueryFilter{
			TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateActive},
		},
		mockDatabase,
	).Return(nil, nil).Once()
	mockCrypto.On(
		"NewEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		mockDatabase,
	).Return(testEncKey, nil)
	uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
	assert.Nil(err)

	testKey := uuid.NewString()
	testRecord := models.Record{ID: uuid.NewString()}

	mockDatabase.On(
		"GetRecordByName",
		mock.AnythingOfType("context.backgroundCtx"),
		testKey,
	).Return(testRecord, nil).Once()
	mockDatabase.On(
		"DeleteRecord",
		mock.AnythingOfType("context.backgroundCtx"),
		testRecord.ID,
	).Return(nil).Once()

	assert.Nil(uut.DeleteKey(utCtx, testKey, mockDatabase))
}
