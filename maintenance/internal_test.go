package maintenance

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	"github.com/alwitt/haven/models"
	"github.com/alwitt/haven/store"
	"github.com/apex/log"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/logger"
)

// The two rotations each close with a completion proof — the KEK rotation compares recorded
// key pair IDs, the encryption key rotation leans on the record version foreign key. Neither
// fires through the public API, because the step before it converts everything the check
// looks at. Reaching them means calling the closing step directly, against state staged as
// though the step before it had not run.

// internalFixture a runner over a real database and cryptography engine, reachable as the
// concrete type so the unexported closing steps can be driven directly
type internalFixture struct {
	persistence db.Client
	engine      encryption.CryptographyEngine
	uut         *runner
}

// internalCertFixture absolute path of a certificate fixture
func internalCertFixture(t *testing.T, name string) string {
	path, err := filepath.Abs(filepath.Join("../test/certs", name))
	assert.New(t).Nil(err)
	return path
}

// newInternalFixture prepare a fresh database and a runner against a key pair fixture
func newInternalFixture(utCtx context.Context, t *testing.T, keyPair string) internalFixture {
	assert := assert.New(t)

	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	persistence, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)
	assert.Nil(persistence.RunSQLInTransaction(utCtx, db.DefineTables))

	engine, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
		Persistence:        persistence,
		PrimaryRSACertFile: internalCertFixture(t, keyPair+".crt"),
		PrimaryRSAKeyFile:  internalCertFixture(t, keyPair+".key"),
		KeyCacheTTL:        time.Hour,
	})
	assert.Nil(err)

	instance, err := NewRunner(utCtx, persistence, engine, 0)
	assert.Nil(err)
	impl, ok := instance.(*runner)
	assert.True(ok)

	return internalFixture{persistence: persistence, engine: engine, uut: impl}
}

// state read the current system state
func (f internalFixture) state(
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

// keys read every encryption key
func (f internalFixture) keys(utCtx context.Context, t *testing.T) []models.EncryptionKey {
	assert := assert.New(t)

	var entries []models.EncryptionKey
	assert.Nil(f.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			entries, err = dbClient.ListEncryptionKeys(ctx, db.EncryptionKeyQueryFilter{})
			return err
		},
	))

	return entries
}

// versions read every record version
func (f internalFixture) versions(utCtx context.Context, t *testing.T) []models.RecordVersion {
	assert := assert.New(t)

	var entries []models.RecordVersion
	assert.Nil(f.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			entries, err = dbClient.ListAllRecordVersions(ctx, db.RecordVersionQueryFilter{})
			return err
		},
	))

	return entries
}

// TestCloseKEKRotationRefusesIncompleteRotation verifies that the closing step will not
// return the system to normal operation while any key is still wrapped by the old key pair.
//
// This is the primary RSA key pair rotation's completion proof. The check is a comparison of
// recorded IDs rather than a decryption, because by this point every key is wrapped by a
// pair the runner no longer holds — so it could not verify cryptographically even if it
// wanted to.
func TestCloseKEKRotationRefusesIncompleteRotation(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newInternalFixture(utCtx, t, "self-signed")
	assert.Nil(fixture.uut.Initialize(utCtx))

	// The rotation is open, but nothing has been re-wrapped
	assert.Nil(fixture.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.MarkSystemRotatingKEK(ctx)
		},
	))

	newKEK, err := fixture.engine.LoadKEK(utCtx, encryption.KEKParams{
		CertFile: internalCertFixture(t, "user-root.crt"),
		KeyFile:  internalCertFixture(t, "user-root.key"),
	})
	assert.Nil(err)

	closed := fixture.uut.closeKEKRotation(utCtx, newKEK)
	assert.Error(closed)

	// The failure names the key which did not move, and both key pairs, so the reader can
	// tell which direction the rotation was going
	existing := fixture.keys(utCtx, t)
	assert.Len(existing, 1)
	assert.ErrorContains(closed, existing[0].ID)
	assert.ErrorContains(closed, fixture.engine.KEKID())
	assert.ErrorContains(closed, newKEK.ID())

	// The system stays in the rotation rather than reporting success over unconverted keys
	assert.Equal(models.SystemStateKEKRotating, fixture.state(utCtx, t))
	assert.Equal(fixture.engine.KEKID(), existing[0].KekID)
}

// TestCloseDEKRotationRefusesWhileVersionsRemain verifies that the closing step cannot delete
// a retired key which record versions still reference.
//
// This is the encryption key rotation's completion proof, and it costs nothing to maintain:
// record_versions.enc_key_id is ON DELETE RESTRICT, so the delete the rotation performs last
// fails on exactly the condition — versions left behind — that the drain exists to remove.
// The whole transaction aborts, so the system stays in the rotation state.
func TestCloseDEKRotationRefusesWhileVersionsRemain(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newInternalFixture(utCtx, t, "self-signed")
	assert.Nil(fixture.uut.Initialize(utCtx))

	// A value, so the key has a record version pointing at it
	kvStore, err := store.NewProtectedKVStore(utCtx, fixture.persistence, fixture.engine)
	assert.Nil(err)
	_, _, err = kvStore.RecordKeyValue(utCtx, "alpha", []byte("one"), time.Now().UTC(), nil)
	assert.Nil(err)

	active := fixture.keys(utCtx, t)[0]

	// The rotation is open and the key retired, but the drain never ran
	assert.Nil(fixture.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			if err := dbClient.MarkSystemRotatingDEK(ctx); err != nil {
				return err
			}
			return dbClient.MarkEncryptionKeyRetired(ctx, active.ID)
		},
	))

	closed := fixture.uut.closeDEKRotation(utCtx)
	assert.Error(closed)
	assert.ErrorContains(closed, "record versions may still reference it")
	assert.ErrorContains(closed, active.ID)

	// The transaction aborted whole: the key is still there, so is the data, and the system
	// is still in the rotation
	assert.Len(fixture.keys(utCtx, t), 1)
	assert.Len(fixture.versions(utCtx, t), 1)
	assert.Equal(models.SystemStateDEKRotating, fixture.state(utCtx, t))
}
