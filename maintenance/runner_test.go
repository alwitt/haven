package maintenance_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	"github.com/alwitt/haven/maintenance"
	"github.com/alwitt/haven/models"
	"github.com/alwitt/haven/store"
	"github.com/apex/log"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/logger"
)

// testFixture the pieces a maintenance test drives: a real database, a real cryptography
// engine over a certificate fixture, and a runner over both
type testFixture struct {
	persistence db.Client
	engine      encryption.CryptographyEngine
	uut         maintenance.Runner
}

// certFixture absolute path of a certificate fixture
func certFixture(t *testing.T, name string) string {
	path, err := filepath.Abs(filepath.Join("../test/certs", name))
	assert.New(t).Nil(err)
	return path
}

// newTestFixture prepare a fresh database and a runner against a key pair fixture
func newTestFixture(
	utCtx context.Context, t *testing.T, keyPair string, pageSize int,
) testFixture {
	assert := assert.New(t)

	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	persistence, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)
	assert.Nil(persistence.RunSQLInTransaction(utCtx, db.DefineTables))

	return newTestFixtureOn(utCtx, t, persistence, keyPair, pageSize)
}

// newTestFixtureOn prepare a runner against an existing database, so one database can be
// driven by runners holding different key pairs
func newTestFixtureOn(
	utCtx context.Context,
	t *testing.T,
	persistence db.Client,
	keyPair string,
	pageSize int,
) testFixture {
	assert := assert.New(t)

	engine, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
		Persistence:        persistence,
		PrimaryRSACertFile: certFixture(t, keyPair+".crt"),
		PrimaryRSAKeyFile:  certFixture(t, keyPair+".key"),
		KeyCacheTTL:        time.Hour,
	})
	assert.Nil(err)

	uut, err := maintenance.NewRunner(utCtx, persistence, engine, pageSize)
	assert.Nil(err)

	return testFixture{persistence: persistence, engine: engine, uut: uut}
}

// newStore build a KV store over the same database and cryptography engine
func (f testFixture) newStore(utCtx context.Context, t *testing.T) store.ProtectedKVStore {
	uut, err := store.NewProtectedKVStore(utCtx, f.persistence, f.engine)
	assert.New(t).Nil(err)
	return uut
}

// assertStoreRefused verify a KV store can't be opened against the system as it stands
func (f testFixture) assertStoreRefused(utCtx context.Context, t *testing.T) {
	assert := assert.New(t)
	uut, err := store.NewProtectedKVStore(utCtx, f.persistence, f.engine)
	assert.Nil(uut)
	assert.Error(err)
}

// systemState read the current system state
func (f testFixture) systemState(
	utCtx context.Context, t *testing.T,
) models.SystemStateENUMType {
	assert := assert.New(t)

	var state models.SystemStateENUMType
	assert.Nil(f.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			params, err := dbClient.GetSystemParamEntry(ctx)
			state = params.State
			return err
		},
	))

	return state
}

// encryptionKeys read every encryption key
func (f testFixture) encryptionKeys(
	utCtx context.Context, t *testing.T,
) []models.EncryptionKey {
	assert := assert.New(t)

	var keys []models.EncryptionKey
	assert.Nil(f.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			keys, err = dbClient.ListEncryptionKeys(ctx, db.EncryptionKeyQueryFilter{})
			return err
		},
	))

	return keys
}

// recordVersions read every record version
func (f testFixture) recordVersions(
	utCtx context.Context, t *testing.T,
) []models.RecordVersion {
	assert := assert.New(t)

	var versions []models.RecordVersion
	assert.Nil(f.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			versions, err = dbClient.ListAllRecordVersions(ctx, db.RecordVersionQueryFilter{})
			return err
		},
	))

	return versions
}

// auditEventTypes read the audit log, in the order it was written
func (f testFixture) auditEventTypes(
	utCtx context.Context, t *testing.T,
) []models.SystemEventTypeENUMType {
	assert := assert.New(t)

	var events []models.SystemEventAudit
	assert.Nil(f.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			events, err = dbClient.ListSystemEvents(ctx, db.SystemEventQueryFilter{})
			return err
		},
	))

	types := []models.SystemEventTypeENUMType{}
	for _, entry := range events {
		types = append(types, entry.EventType)
	}
	return types
}

// writeValues record a value under each key through a KV store
func (f testFixture) writeValues(
	utCtx context.Context, t *testing.T, values map[string][]byte,
) {
	assert := assert.New(t)
	kvStore := f.newStore(utCtx, t)

	for key, value := range values {
		_, _, err := kvStore.RecordKeyValue(utCtx, key, value, time.Now().UTC(), nil)
		assert.Nil(err, "recording %s", key)
	}
}

// assertValuesReadable verify every value still reads back through a KV store
func (f testFixture) assertValuesReadable(
	utCtx context.Context, t *testing.T, values map[string][]byte,
) {
	assert := assert.New(t)
	kvStore := f.newStore(utCtx, t)

	for key, value := range values {
		_, versions, err := kvStore.ListKeyVersions(utCtx, key, nil)
		assert.Nil(err, "listing %s", key)
		assert.Len(versions, 1, "listing %s", key)

		readBack, err := kvStore.GetValueOfKeyAtVersion(utCtx, versions[0], nil)
		assert.Nil(err, "reading %s", key)
		assert.Equal(value, readBack, "reading %s", key)
	}
}

func TestMaintenanceStatus(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newTestFixture(utCtx, t, "self-signed", 0)

	// Before initialization: no keys, and the READY invariant does not hold
	status, err := fixture.uut.Status(utCtx)
	assert.Nil(err)
	assert.Equal(models.SystemStatePreInit, status.State)
	assert.Equal(fixture.engine.KEKID(), status.KEKID)
	assert.Empty(status.ActiveKeys)
	assert.Empty(status.RetiredKeys)
	assert.Zero(status.VersionsUnderRetiredKeys)
	assert.Zero(status.KeysUnderAnotherKEK)
	assert.False(status.ReadyInvariantHolds)

	// After initialization: exactly one active key, and nothing outstanding
	assert.Nil(fixture.uut.Initialize(utCtx))
	status, err = fixture.uut.Status(utCtx)
	assert.Nil(err)
	assert.Equal(models.SystemStateReady, status.State)
	assert.Len(status.ActiveKeys, 1)
	assert.Empty(status.RetiredKeys)
	assert.Zero(status.KeysUnderAnotherKEK)
	assert.True(status.ReadyInvariantHolds)

	// Mid rotation: the work still to do is counted
	fixture.writeValues(utCtx, t, map[string][]byte{
		"alpha": []byte("one"), "bravo": []byte("two"), "charlie": []byte("three"),
	})
	assert.Nil(fixture.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			if err := dbClient.MarkSystemRotatingDEK(ctx); err != nil {
				return err
			}
			return dbClient.MarkEncryptionKeyRetired(ctx, status.ActiveKeys[0].ID)
		},
	))

	status, err = fixture.uut.Status(utCtx)
	assert.Nil(err)
	assert.Equal(models.SystemStateDEKRotating, status.State)
	assert.Empty(status.ActiveKeys)
	assert.Len(status.RetiredKeys, 1)
	assert.EqualValues(3, status.VersionsUnderRetiredKeys)
	assert.False(status.ReadyInvariantHolds)
}

// TestMaintenanceGuardRails verifies that every action refuses to run from a state it does
// not belong in, and says which state the system is actually in.
func TestMaintenanceGuardRails(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// Before initialization, nothing but Initialize may run
	{
		fixture := newTestFixture(utCtx, t, "self-signed", 0)

		refused := fixture.uut.RotateEncryptionKey(utCtx)
		assert.ErrorContains(refused, string(models.SystemStatePreInit))

		// Every action reports a maintenance failure, whatever refused it underneath
		var maintenanceErr models.MaintenanceError
		assert.True(errors.As(refused, &maintenanceErr))

		assert.ErrorContains(fixture.uut.RotateKEK(utCtx, encryption.KEKParams{
			CertFile: certFixture(t, "user-root.crt"), KeyFile: certFixture(t, "user-root.key"),
		}), string(models.SystemStatePreInit))

		_, err := fixture.uut.ListUndecryptableVersions(utCtx)
		assert.ErrorContains(err, string(models.SystemStatePreInit))
		assert.True(errors.As(err, &maintenanceErr))
		_, err = fixture.uut.PurgeUndecryptableVersions(utCtx)
		assert.ErrorContains(err, string(models.SystemStatePreInit))

		assert.Equal(models.SystemStatePreInit, fixture.systemState(utCtx, t))
	}

	// Once ready, Initialize may not run again, and the undecryptable scans have no scope
	{
		fixture := newTestFixture(utCtx, t, "self-signed", 0)
		assert.Nil(fixture.uut.Initialize(utCtx))

		assert.ErrorContains(fixture.uut.Initialize(utCtx), string(models.SystemStateReady))

		_, err := fixture.uut.ListUndecryptableVersions(utCtx)
		assert.ErrorContains(err, string(models.SystemStateReady))
		_, err = fixture.uut.PurgeUndecryptableVersions(utCtx)
		assert.ErrorContains(err, string(models.SystemStateReady))

		// Initialize refused rather than minting a second key
		keys := fixture.encryptionKeys(utCtx, t)
		assert.Len(keys, 1)
	}

	// One rotation can't start while the other is outstanding
	{
		fixture := newTestFixture(utCtx, t, "self-signed", 0)
		assert.Nil(fixture.uut.Initialize(utCtx))
		assert.Nil(fixture.persistence.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				return dbClient.MarkSystemRotatingKEK(ctx)
			},
		))

		assert.ErrorContains(
			fixture.uut.RotateEncryptionKey(utCtx), string(models.SystemStateKEKRotating),
		)
		assert.Equal(models.SystemStateKEKRotating, fixture.systemState(utCtx, t))
	}
}
