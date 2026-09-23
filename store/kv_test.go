package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alwitt/goutils"
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

// newTestStoreMocks wire a persistence client which hands every transaction the same mock
// database
//
// The callback's error is returned as is, the way UseDatabaseInTransaction does, so a
// transaction which fails reaches the caller rather than the test harness.
func newTestStoreMocks(utCtx context.Context, t *testing.T) (
	*mockdb.Client, *mockdb.Database, *mockencryption.CryptographyEngine,
) {
	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)
	mockCrypto := mockencryption.NewCryptographyEngine(t)

	mockDBClient.On(
		"UseDatabaseInTransaction",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.Anything,
	).Return(func(
		_ context.Context, coreLogic func(ctx context.Context, dbClient db.Database) error,
	) error {
		return coreLogic(utCtx, mockDatabase)
	}).Maybe()

	return mockDBClient, mockDatabase, mockCrypto
}

// expectActiveKeyListing set up the encryption key listing the store constructor makes
func expectActiveKeyListing(
	mockDatabase *mockdb.Database,
	mockCrypto *mockencryption.CryptographyEngine,
	keys []models.EncryptionKey,
) {
	mockCrypto.On(
		"ListEncryptionKeys",
		mock.AnythingOfType("context.backgroundCtx"),
		db.EncryptionKeyQueryFilter{
			TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateActive},
		},
		mockDatabase,
	).Return(keys, nil).Once()
}

// newTestStore build a store whose constructor finds a system ready for normal operation,
// holding one active encryption key
func newTestStore(utCtx context.Context, t *testing.T) (
	store.ProtectedKVStore,
	*mockdb.Database,
	*mockencryption.CryptographyEngine,
	models.EncryptionKey,
) {
	assert := assert.New(t)

	mockDBClient, mockDatabase, mockCrypto := newTestStoreMocks(utCtx, t)

	testEncKey := models.EncryptionKey{
		ID: uuid.NewString(), State: models.EncryptionKeyStateActive,
	}

	mockDatabase.On(
		"GetSystemParamEntry", mock.AnythingOfType("context.backgroundCtx"),
	).Return(models.SystemParams{State: models.SystemStateReady}, nil).Once()
	expectActiveKeyListing(mockDatabase, mockCrypto, []models.EncryptionKey{testEncKey})

	uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
	assert.Nil(err)

	return uut, mockDatabase, mockCrypto, testEncKey
}

// TestKVStoreInit verifies what the store constructor demands of the system it opens
// against.
//
// No mock here registers a NewEncryptionKey expectation. Minting is a maintenance action
// and nothing else, so a constructor which still mints fails these as an unexpected call.
func TestKVStoreInit(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// A system ready for normal operation, holding one active key
	{
		mockDBClient, mockDatabase, mockCrypto := newTestStoreMocks(utCtx, t)
		testEncKey := models.EncryptionKey{
			ID: uuid.NewString(), State: models.EncryptionKeyStateActive,
		}

		mockDatabase.On(
			"GetSystemParamEntry", mock.AnythingOfType("context.backgroundCtx"),
		).Return(models.SystemParams{State: models.SystemStateReady}, nil).Once()
		expectActiveKeyListing(mockDatabase, mockCrypto, []models.EncryptionKey{testEncKey})

		uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
		assert.Nil(err)
		assert.NotNil(uut)
	}

	// More than one active key is outside the system's invariants, and not the
	// constructor's to adjudicate: it takes the first and opens
	{
		mockDBClient, mockDatabase, mockCrypto := newTestStoreMocks(utCtx, t)
		firstKey := models.EncryptionKey{
			ID: uuid.NewString(), State: models.EncryptionKeyStateActive,
		}
		secondKey := models.EncryptionKey{
			ID: uuid.NewString(), State: models.EncryptionKeyStateActive,
		}

		mockDatabase.On(
			"GetSystemParamEntry", mock.AnythingOfType("context.backgroundCtx"),
		).Return(models.SystemParams{State: models.SystemStateReady}, nil).Once()
		expectActiveKeyListing(
			mockDatabase, mockCrypto, []models.EncryptionKey{firstKey, secondKey},
		)

		uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
		assert.Nil(err)
		assert.NotNil(uut)
	}

	// A system a maintenance action owns is closed to KV stores, and the refusal names the
	// state so the operator knows which action to complete
	for _, state := range []models.SystemStateENUMType{
		models.SystemStatePreInit,
		models.SystemStateDEKRotating,
		models.SystemStateKEKRotating,
	} {
		mockDBClient, mockDatabase, mockCrypto := newTestStoreMocks(utCtx, t)

		// The listing is never reached, so no expectation is registered for it
		mockDatabase.On(
			"GetSystemParamEntry", mock.AnythingOfType("context.backgroundCtx"),
		).Return(models.SystemParams{State: state}, nil).Once()

		uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
		assert.Nil(uut, string(state))
		assert.ErrorContains(err, string(state), string(state))

		var storeErr models.KVStoreError
		assert.True(errors.As(err, &storeErr), string(state))
	}

	// A ready system with no key to encrypt under is unusable, and says so rather than
	// minting one
	{
		mockDBClient, mockDatabase, mockCrypto := newTestStoreMocks(utCtx, t)

		mockDatabase.On(
			"GetSystemParamEntry", mock.AnythingOfType("context.backgroundCtx"),
		).Return(models.SystemParams{State: models.SystemStateReady}, nil).Once()
		expectActiveKeyListing(mockDatabase, mockCrypto, []models.EncryptionKey{})

		uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
		assert.Nil(uut)
		assert.ErrorContains(err, "no active encryption key")
	}
}

func TestKVStoreRecordNewKey(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	uut, mockDatabase, mockCrypto, testEncKey := newTestStore(utCtx, t)

	testKey := uuid.NewString()
	testValue := uuid.NewString()
	testEncValue := uuid.NewString()
	testNonce := uuid.NewString()
	timestamp := time.Now().UTC()

	// Record a new uut and value
	testRecord := models.Record{ID: uuid.NewString()}
	testVersion := models.RecordVersion{ID: uuid.NewString()}
	var additional []byte
	var versionID string
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
		mock.AnythingOfType("[]uint8"),
		mockDatabase,
	).Run(func(args mock.Arguments) {
		var ok bool
		additional, ok = args.Get(3).([]byte)
		assert.True(ok)
	}).Return(testEncKey, encryption.EncryptedData{
		CipherText: []byte(testEncValue), Nonce: []byte(testNonce),
	}, nil).Once()
	mockDatabase.On(
		"DefineNewVersionForRecord",
		mock.AnythingOfType("context.backgroundCtx"),
		testRecord,
		mock.AnythingOfType("string"),
		testEncKey,
		[]byte(testEncValue),
		[]byte(testNonce),
		timestamp,
	).Run(func(args mock.Arguments) {
		var ok bool
		versionID, ok = args.Get(2).(string)
		assert.True(ok)
	}).Return(testVersion, nil).Once()
	theRecord, theVersion, err := uut.RecordKeyValue(
		utCtx, testKey, []byte(testValue), timestamp, mockDatabase,
	)
	assert.Nil(err)
	assert.Equal(testRecord, theRecord)
	assert.Equal(testVersion, theVersion)

	// The cipher text was bound to the row it was stored under
	assert.NotEmpty(versionID)
	assert.Equal(
		models.RecordVersion{
			ID: versionID, RecordID: testRecord.ID, EncKeyID: testEncKey.ID,
		}.AssociatedData(),
		additional,
	)
}

// TestKVStoreRecordKeyValueRecordLookup covers how RecordKeyValue reacts to the record
// lookup: a missing record is created, any other lookup failure aborts, and an empty value
// is refused before either happens
func TestKVStoreRecordKeyValueRecordLookup(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	uut, mockDatabase, mockCrypto, testEncKey := newTestStore(utCtx, t)

	timestamp := time.Now().UTC()

	// Case 0: the key is unknown, so a record is defined for it first
	{
		testKey := uuid.NewString()
		testValue := uuid.NewString()
		testRecord := models.Record{ID: uuid.NewString(), Name: testKey}
		testVersion := models.RecordVersion{ID: uuid.NewString(), RecordID: testRecord.ID}
		mockDatabase.On(
			"GetRecordByName",
			mock.AnythingOfType("context.backgroundCtx"),
			testKey,
		).Return(models.Record{}, goutils.NewNotFoundError("unknown", nil, false)).Once()
		mockDatabase.On(
			"DefineNewRecord",
			mock.AnythingOfType("context.backgroundCtx"),
			testKey,
		).Return(testRecord, nil).Once()
		mockCrypto.On(
			"EncryptData",
			mock.AnythingOfType("context.backgroundCtx"),
			testEncKey.ID,
			[]byte(testValue),
			mock.AnythingOfType("[]uint8"),
			mockDatabase,
		).Return(testEncKey, encryption.EncryptedData{
			CipherText: []byte(uuid.NewString()), Nonce: []byte(uuid.NewString()),
		}, nil).Once()
		mockDatabase.On(
			"DefineNewVersionForRecord",
			mock.AnythingOfType("context.backgroundCtx"),
			testRecord,
			mock.AnythingOfType("string"),
			testEncKey,
			mock.AnythingOfType("[]uint8"),
			mock.AnythingOfType("[]uint8"),
			timestamp,
		).Return(testVersion, nil).Once()
		theRecord, theVersion, err := uut.RecordKeyValue(
			utCtx, testKey, []byte(testValue), timestamp, mockDatabase,
		)
		assert.Nil(err)
		assert.Equal(testRecord, theRecord)
		assert.Equal(testVersion, theVersion)
	}

	// Case 1: the lookup fails for another reason, so no record is defined and the write
	// aborts. No DefineNewRecord expectation is registered, so a call would fail the test.
	{
		testKey := uuid.NewString()
		mockDatabase.On(
			"GetRecordByName",
			mock.AnythingOfType("context.backgroundCtx"),
			testKey,
		).Return(models.Record{}, goutils.NewSQLError("connection lost", nil, false)).Once()
		_, _, err := uut.RecordKeyValue(
			utCtx, testKey, []byte(uuid.NewString()), timestamp, mockDatabase,
		)
		assert.Error(err)
	}

	// Case 2: an empty value is refused before any persistence or crypto call
	{
		for _, value := range [][]byte{nil, {}} {
			_, _, err := uut.RecordKeyValue(utCtx, uuid.NewString(), value, timestamp, mockDatabase)
			assert.ErrorContains(err, "is empty")
		}
	}
}

func TestKVStoreListVersions(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	uut, mockDatabase, _, _ := newTestStore(utCtx, t)

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

	uut, mockDatabase, mockCrypto, testEncKey := newTestStore(utCtx, t)

	testVersion := models.RecordVersion{
		ID:       uuid.NewString(),
		RecordID: uuid.NewString(),
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
			testVersion.AssociatedData(),
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
			testVersion.AssociatedData(),
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

	uut, mockDatabase, _, _ := newTestStore(utCtx, t)

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

// assertStoreBoundaryError verify a failure is stamped at the store's public boundary while
// the cause underneath it stays reachable.
//
// DESIGN §11: each application-facing layer stamps its own error type at its public boundary
// only, and the types beneath it survive. Both halves matter to a caller — the outer type is
// how it knows which layer failed, the inner one is how it tells a missing row from a failed
// write — so both are asserted on every path.
func assertStoreBoundaryError(t *testing.T, err error, names string) {
	assert := assert.New(t)

	assert.Error(err)
	assert.ErrorContains(err, names)

	var storeErr models.KVStoreError
	assert.True(errors.As(err, &storeErr), "the outermost error is the store's own type")

	var injectedErr goutils.SQLError
	assert.True(errors.As(err, &injectedErr), "the cause survives the store's wrapping")
}

// TestKVStoreConstructorReportsFailures verifies that a constructor which cannot read the
// system it is opening against says why, rather than handing back an unusable store.
func TestKVStoreConstructorReportsFailures(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	injected := goutils.NewSQLError("the database said no", nil, false)

	tests := []struct {
		name string
		wire func(*mockdb.Database, *mockencryption.CryptographyEngine)
	}{
		{
			name: "the system parameter entry is unreadable",
			wire: func(mockDatabase *mockdb.Database, _ *mockencryption.CryptographyEngine) {
				mockDatabase.On(
					"GetSystemParamEntry", mock.AnythingOfType("context.backgroundCtx"),
				).Return(models.SystemParams{}, injected).Once()
			},
		},
		{
			name: "the encryption keys are unreadable",
			wire: func(
				mockDatabase *mockdb.Database, mockCrypto *mockencryption.CryptographyEngine,
			) {
				mockDatabase.On(
					"GetSystemParamEntry", mock.AnythingOfType("context.backgroundCtx"),
				).Return(models.SystemParams{State: models.SystemStateReady}, nil).Once()
				mockCrypto.On(
					"ListEncryptionKeys",
					mock.AnythingOfType("context.backgroundCtx"),
					mock.Anything,
					mockDatabase,
				).Return(nil, injected).Once()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)

			mockDBClient, mockDatabase, mockCrypto := newTestStoreMocks(utCtx, t)
			test.wire(mockDatabase, mockCrypto)

			uut, err := store.NewProtectedKVStore(utCtx, mockDBClient, mockCrypto)
			assert.Nil(uut)
			assertStoreBoundaryError(t, err, "working encryption key")
		})
	}
}

// TestKVStoreOperationsReportTheirCause verifies that every way an operation can fail
// underneath the store reaches the caller as a store failure which still carries what
// actually went wrong.
func TestKVStoreOperationsReportTheirCause(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	injected := goutils.NewSQLError("the database said no", nil, false)
	anyCtx := mock.AnythingOfType("context.backgroundCtx")

	faultKey := "alpha"
	faultVersion := models.RecordVersion{
		ID: uuid.NewString(), RecordID: uuid.NewString(), EncKeyID: uuid.NewString(),
	}
	faultRecord := models.Record{ID: faultVersion.RecordID, Name: faultKey}

	tests := []struct {
		name  string
		wire  func(*mockdb.Database, *mockencryption.CryptographyEngine, models.EncryptionKey)
		drive func(store.ProtectedKVStore, *mockdb.Database) error
		names string
	}{
		{
			name: "recording a value cannot create the record",
			wire: func(
				mockDatabase *mockdb.Database, _ *mockencryption.CryptographyEngine,
				_ models.EncryptionKey,
			) {
				mockDatabase.On("GetRecordByName", anyCtx, faultKey).
					Return(models.Record{}, goutils.NewNotFoundError("no such record", nil, false)).Once()
				mockDatabase.On("DefineNewRecord", anyCtx, faultKey).
					Return(models.Record{}, injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				_, _, err := uut.RecordKeyValue(
					utCtx, faultKey, []byte("a value"), time.Now().UTC(), mockDatabase,
				)
				return err
			},
			names: faultKey,
		},
		{
			name: "recording a value cannot encrypt it",
			wire: func(
				mockDatabase *mockdb.Database, mockCrypto *mockencryption.CryptographyEngine,
				encKey models.EncryptionKey,
			) {
				mockDatabase.On("GetRecordByName", anyCtx, faultKey).Return(faultRecord, nil).Once()
				mockCrypto.On(
					"EncryptData", anyCtx, encKey.ID, mock.Anything, mock.Anything, mockDatabase,
				).Return(models.EncryptionKey{}, encryption.EncryptedData{}, injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				_, _, err := uut.RecordKeyValue(
					utCtx, faultKey, []byte("a value"), time.Now().UTC(), mockDatabase,
				)
				return err
			},
			names: faultKey,
		},
		{
			name: "recording a value cannot insert the version",
			wire: func(
				mockDatabase *mockdb.Database, mockCrypto *mockencryption.CryptographyEngine,
				encKey models.EncryptionKey,
			) {
				mockDatabase.On("GetRecordByName", anyCtx, faultKey).Return(faultRecord, nil).Once()
				mockCrypto.On(
					"EncryptData", anyCtx, encKey.ID, mock.Anything, mock.Anything, mockDatabase,
				).Return(encKey, encryption.EncryptedData{
					CipherText: []byte("sealed"), Nonce: []byte("nonce"),
				}, nil).Once()
				mockDatabase.On(
					"DefineNewVersionForRecord",
					anyCtx, faultRecord, mock.AnythingOfType("string"), encKey,
					mock.Anything, mock.Anything, mock.Anything,
				).Return(models.RecordVersion{}, injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				_, _, err := uut.RecordKeyValue(
					utCtx, faultKey, []byte("a value"), time.Now().UTC(), mockDatabase,
				)
				return err
			},
			names: faultKey,
		},
		{
			name: "listing versions cannot find the key",
			wire: func(
				mockDatabase *mockdb.Database, _ *mockencryption.CryptographyEngine,
				_ models.EncryptionKey,
			) {
				mockDatabase.On("GetRecordByName", anyCtx, faultKey).
					Return(models.Record{}, injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				_, _, err := uut.ListKeyVersions(utCtx, faultKey, mockDatabase)
				return err
			},
			names: faultKey,
		},
		{
			name: "listing versions cannot read them",
			wire: func(
				mockDatabase *mockdb.Database, _ *mockencryption.CryptographyEngine,
				_ models.EncryptionKey,
			) {
				mockDatabase.On("GetRecordByName", anyCtx, faultKey).Return(faultRecord, nil).Once()
				mockDatabase.On("ListVersionsOfOneRecord", anyCtx, faultRecord, mock.Anything).
					Return(nil, injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				_, _, err := uut.ListKeyVersions(utCtx, faultKey, mockDatabase)
				return err
			},
			names: faultKey,
		},
		{
			name: "reading a version by ID cannot find it",
			wire: func(
				mockDatabase *mockdb.Database, _ *mockencryption.CryptographyEngine,
				_ models.EncryptionKey,
			) {
				mockDatabase.On("GetRecordVersion", anyCtx, faultVersion.ID).
					Return(models.RecordVersion{}, injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				_, err := uut.GetValueOfKeyAtVersionID(utCtx, faultVersion.ID, mockDatabase)
				return err
			},
			names: faultVersion.ID,
		},
		{
			name: "reading a version by ID cannot decrypt it",
			wire: func(
				mockDatabase *mockdb.Database, mockCrypto *mockencryption.CryptographyEngine,
				_ models.EncryptionKey,
			) {
				mockDatabase.On("GetRecordVersion", anyCtx, faultVersion.ID).
					Return(faultVersion, nil).Once()
				mockCrypto.On(
					"DecryptData", anyCtx, faultVersion.EncKeyID, mock.Anything, mock.Anything,
					mockDatabase,
				).Return(models.EncryptionKey{}, nil, injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				_, err := uut.GetValueOfKeyAtVersionID(utCtx, faultVersion.ID, mockDatabase)
				return err
			},
			names: faultVersion.ID,
		},
		{
			name: "reading a supplied version cannot decrypt it",
			wire: func(
				mockDatabase *mockdb.Database, mockCrypto *mockencryption.CryptographyEngine,
				_ models.EncryptionKey,
			) {
				mockCrypto.On(
					"DecryptData", anyCtx, faultVersion.EncKeyID, mock.Anything, mock.Anything,
					mockDatabase,
				).Return(models.EncryptionKey{}, nil, injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				_, err := uut.GetValueOfKeyAtVersion(utCtx, faultVersion, mockDatabase)
				return err
			},
			names: faultVersion.ID,
		},
		{
			name: "deleting a key cannot find it",
			wire: func(
				mockDatabase *mockdb.Database, _ *mockencryption.CryptographyEngine,
				_ models.EncryptionKey,
			) {
				mockDatabase.On("GetRecordByName", anyCtx, faultKey).
					Return(models.Record{}, injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				return uut.DeleteKey(utCtx, faultKey, mockDatabase)
			},
			names: faultKey,
		},
		{
			name: "deleting a key cannot remove it",
			wire: func(
				mockDatabase *mockdb.Database, _ *mockencryption.CryptographyEngine,
				_ models.EncryptionKey,
			) {
				mockDatabase.On("GetRecordByName", anyCtx, faultKey).Return(faultRecord, nil).Once()
				mockDatabase.On("DeleteRecord", anyCtx, faultRecord.ID).Return(injected).Once()
			},
			drive: func(uut store.ProtectedKVStore, mockDatabase *mockdb.Database) error {
				return uut.DeleteKey(utCtx, faultKey, mockDatabase)
			},
			names: faultKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uut, mockDatabase, mockCrypto, encKey := newTestStore(utCtx, t)
			test.wire(mockDatabase, mockCrypto, encKey)

			assertStoreBoundaryError(t, test.drive(uut, mockDatabase), test.names)
		})
	}
}
