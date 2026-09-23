package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestDBRecordDataGuardRails verifies that the record data API is open only while the
// system is READY.
//
// A record written while a maintenance action owns the cryptographic material would be
// missed by a key rotation, so the persistence layer refuses the write outright.
func TestDBRecordDataGuardRails(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut := newTestDBClient(utCtx, t)

	// Prepare one record, one key and one version to operate on later
	markSystemReady(utCtx, t, uut)

	var existing models.Record
	var key models.EncryptionKey
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			if existing, err = dbClient.DefineNewRecord(ctx, uuid.NewString()); err != nil {
				return err
			}
			key, err = dbClient.RecordEncryptionKey(ctx, []byte(uuid.NewString()), testKekID)
			return err
		},
	))

	// Every state which is not READY closes the record data API
	for _, closedState := range []models.SystemStateENUMType{
		models.SystemStateDEKRotating, models.SystemStateKEKRotating,
	} {
		assert.Nil(uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				switch closedState {
				case models.SystemStateDEKRotating:
					return dbClient.MarkSystemRotatingDEK(ctx)
				default:
					return dbClient.MarkSystemRotatingKEK(ctx)
				}
			},
		))

		assert.Error(uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				_, err := dbClient.DefineNewRecord(ctx, uuid.NewString())
				return err
			},
		), "DefineNewRecord must be refused in %s", closedState)

		assert.Error(uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				_, err := dbClient.DefineNewVersionForRecord(
					ctx, existing, db.NewRecordVersionID(), key,
					[]byte(uuid.NewString()), []byte(uuid.NewString()), time.Now().UTC(),
				)
				return err
			},
		), "DefineNewVersionForRecord must be refused in %s", closedState)

		assert.Error(uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				return dbClient.DeleteRecord(ctx, existing.ID)
			},
		), "DeleteRecord must be refused in %s", closedState)

		// Reading is never blocked: every version stays decryptable throughout a rotation
		assert.Nil(uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				_, err := dbClient.GetRecord(ctx, existing.ID)
				return err
			},
		), "GetRecord must stay available in %s", closedState)

		markSystemReady(utCtx, t, uut)
	}

	// Back in READY, the same calls succeed
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			_, err := dbClient.DefineNewRecord(ctx, uuid.NewString())
			return err
		},
	))
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.DeleteRecord(ctx, existing.ID)
		},
	))
}

// TestDBRecordDataGuardRailsBeforeInit verifies the record data API is closed before the
// system has ever been initialized.
func TestDBRecordDataGuardRailsBeforeInit(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut := newTestDBClient(utCtx, t)

	assert.Equal(models.SystemStatePreInit, readSystemState(utCtx, t, uut))

	assert.Error(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			_, err := dbClient.DefineNewRecord(ctx, uuid.NewString())
			return err
		},
	))

	// Encryption keys are exempt: a maintenance action mints the first one to reach READY
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			_, err := dbClient.RecordEncryptionKey(ctx, []byte(uuid.NewString()), testKekID)
			return err
		},
	))
}

// TestDBUpdateRecordVersionEncryption verifies that re-encrypting a version in place
// replaces only the encryption columns, and works while a rotation is underway.
func TestDBUpdateRecordVersionEncryption(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut := newTestDBClient(utCtx, t)
	markSystemReady(utCtx, t, uut)

	var record models.Record
	var oldKey, newKey models.EncryptionKey
	var version models.RecordVersion

	oldValue := []byte(uuid.NewString())
	oldNonce := []byte(uuid.NewString())
	timestamp := time.Now().UTC().Truncate(time.Millisecond)

	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			if record, err = dbClient.DefineNewRecord(ctx, uuid.NewString()); err != nil {
				return err
			}
			if oldKey, err = dbClient.RecordEncryptionKey(
				ctx, []byte(uuid.NewString()), testKekID,
			); err != nil {
				return err
			}
			if newKey, err = dbClient.RecordEncryptionKey(
				ctx, []byte(uuid.NewString()), testKekID,
			); err != nil {
				return err
			}
			version, err = dbClient.DefineNewVersionForRecord(
				ctx, record, db.NewRecordVersionID(), oldKey, oldValue, oldNonce, timestamp,
			)
			return err
		},
	))

	// A rotation owns the system while versions are re-encrypted
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.MarkSystemRotatingDEK(ctx)
		},
	))

	newValue := []byte(uuid.NewString())
	newNonce := []byte(uuid.NewString())
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			updated, err := dbClient.UpdateRecordVersionEncryption(
				ctx, version.ID, newKey, newValue, newNonce,
			)
			if err != nil {
				return err
			}
			assert.Equal(version.ID, updated.ID)
			assert.Equal(newKey.ID, updated.EncKeyID)
			return nil
		},
	))

	// The version keeps its identity and its place in the record's history
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			stored, err := dbClient.GetRecordVersion(ctx, version.ID)
			if err != nil {
				return err
			}
			assert.Equal(version.ID, stored.ID)
			assert.Equal(record.ID, stored.RecordID)
			assert.Equal(timestamp.Unix(), stored.CreatedAt.Unix())
			assert.Equal(newKey.ID, stored.EncKeyID)
			assert.Equal(newValue, stored.EncValue)
			assert.Equal(newNonce, stored.EncNonce)
			return nil
		},
	))

	// The old key is now unreferenced, so it can be deleted
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.DeleteEncryptionKey(ctx, oldKey.ID)
		},
	))

	// Re-encryption is not audited; a rotation over a large store would drown the log
	var events []models.SystemEventAudit
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			events, err = dbClient.ListSystemEvents(ctx, db.SystemEventQueryFilter{})
			return err
		},
	))
	for _, entry := range events {
		assert.NotEqual(models.SystemEventTypePurgeRecordVersion, entry.EventType)
	}

	// An unknown version is reported as not found
	assert.ErrorAs(
		uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				_, err := dbClient.UpdateRecordVersionEncryption(
					ctx, db.NewRecordVersionID(), newKey, newValue, newNonce,
				)
				return err
			},
		),
		&goutils.NotFoundError{},
	)
}

// TestDBPurgeRecordVersion verifies that purging one version leaves its record and its
// sibling versions intact, and audits the destruction.
func TestDBPurgeRecordVersion(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut := newTestDBClient(utCtx, t)
	markSystemReady(utCtx, t, uut)

	var record models.Record
	var key models.EncryptionKey
	var doomed, sibling models.RecordVersion
	recordName := uuid.NewString()

	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			if record, err = dbClient.DefineNewRecord(ctx, recordName); err != nil {
				return err
			}
			if key, err = dbClient.RecordEncryptionKey(
				ctx, []byte(uuid.NewString()), testKekID,
			); err != nil {
				return err
			}
			if doomed, err = dbClient.DefineNewVersionForRecord(
				ctx, record, db.NewRecordVersionID(), key,
				[]byte(uuid.NewString()), []byte(uuid.NewString()), time.Now().UTC(),
			); err != nil {
				return err
			}
			sibling, err = dbClient.DefineNewVersionForRecord(
				ctx, record, db.NewRecordVersionID(), key,
				[]byte(uuid.NewString()), []byte(uuid.NewString()), time.Now().UTC(),
			)
			return err
		},
	))

	// Purging is a maintenance operation, and runs while a rotation owns the system
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.MarkSystemRotatingDEK(ctx)
		},
	))

	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.PurgeRecordVersion(ctx, doomed.ID)
		},
	))

	// The purged version is gone
	assert.ErrorAs(
		uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				_, err := dbClient.GetRecordVersion(ctx, doomed.ID)
				return err
			},
		),
		&goutils.NotFoundError{},
	)

	// Its record and its sibling are untouched
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			if _, err := dbClient.GetRecord(ctx, record.ID); err != nil {
				return err
			}
			_, err := dbClient.GetRecordVersion(ctx, sibling.ID)
			return err
		},
	))

	// Every purge is audited: the row is the only record the data ever existed
	var events []models.SystemEventAudit
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			events, err = dbClient.ListSystemEvents(ctx, db.SystemEventQueryFilter{
				EventTypes: []models.SystemEventTypeENUMType{
					models.SystemEventTypePurgeRecordVersion,
				},
			})
			return err
		},
	))
	assert.Len(events, 1)

	validate := newTestValidator(t)
	metadata, err := events[0].ParseMetadata(validate)
	assert.Nil(err)
	parsed, ok := metadata.(models.SystemEventRecordVersionRelated)
	assert.True(ok)
	assert.Equal(doomed.ID, parsed.VersionID)
	assert.Equal(record.ID, parsed.RecordID)
	assert.Equal(recordName, parsed.RecordName)

	// An unknown version is reported as not found
	assert.ErrorAs(
		uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				return dbClient.PurgeRecordVersion(ctx, db.NewRecordVersionID())
			},
		),
		&goutils.NotFoundError{},
	)
}
