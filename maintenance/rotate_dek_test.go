package maintenance_test

import (
	"context"
	"errors"
	"testing"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

func TestMaintenanceInitialize(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newTestFixture(utCtx, t, "self-signed", 0)

	assert.Equal(models.SystemStatePreInit, fixture.systemState(utCtx, t))

	assert.Nil(fixture.uut.Initialize(utCtx))
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))

	// Exactly one key, active, stamped with the key pair which wrapped it
	keys := fixture.encryptionKeys(utCtx, t)
	assert.Len(keys, 1)
	assert.Equal(models.EncryptionKeyStateActive, keys[0].State)
	assert.Equal(fixture.engine.KEKID(), keys[0].KekID)

	assert.Equal(
		[]models.SystemEventTypeENUMType{
			models.SystemEventTypeNewEncryptionKey,
			models.SystemEventTypeInitialized,
		},
		fixture.auditEventTypes(utCtx, t),
	)

	// Initializing again would mint a second active key: the transition to READY is a legal
	// no-op from READY, so only the explicit state check stops it
	assert.Error(fixture.uut.Initialize(utCtx))
	assert.Len(fixture.encryptionKeys(utCtx, t), 1)

	// The record data API is open
	fixture.writeValues(utCtx, t, map[string][]byte{"alpha": []byte("one")})
}

// TestMaintenanceRotateEncryptionKey verifies a complete encryption key rotation: every
// version moves onto the new key, the old key is deleted, and the data still reads.
func TestMaintenanceRotateEncryptionKey(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// A page size below the number of versions, so the drain actually pages
	fixture := newTestFixture(utCtx, t, "self-signed", 2)
	assert.Nil(fixture.uut.Initialize(utCtx))

	values := map[string][]byte{
		"alpha": []byte("one"), "bravo": []byte("two"),
		"charlie": []byte("three"), "delta": []byte("four"), "echo": []byte("five"),
	}
	fixture.writeValues(utCtx, t, values)

	originalKey := fixture.encryptionKeys(utCtx, t)[0]

	assert.Nil(fixture.uut.RotateEncryptionKey(utCtx))

	// One active key, which is not the one the data started on
	keys := fixture.encryptionKeys(utCtx, t)
	assert.Len(keys, 1)
	assert.Equal(models.EncryptionKeyStateActive, keys[0].State)
	assert.NotEqual(originalKey.ID, keys[0].ID)
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))

	// Every version moved
	versions := fixture.recordVersions(utCtx, t)
	assert.Len(versions, len(values))
	for _, version := range versions {
		assert.Equal(keys[0].ID, version.EncKeyID)
	}

	// And still reads
	fixture.assertValuesReadable(utCtx, t, values)

	// The rotation is bracketed in the audit log, and the per-version work is not recorded
	assert.Equal(
		[]models.SystemEventTypeENUMType{
			models.SystemEventTypeNewEncryptionKey,
			models.SystemEventTypeInitialized,
			models.SystemEventTypeAddNewRecord,
			models.SystemEventTypeAddNewRecord,
			models.SystemEventTypeAddNewRecord,
			models.SystemEventTypeAddNewRecord,
			models.SystemEventTypeAddNewRecord,
			models.SystemEventTypeDEKRotationStarted,
			models.SystemEventTypeRetireEncryptionKey,
			models.SystemEventTypeNewEncryptionKey,
			models.SystemEventTypeDeleteEncryptionKey,
			models.SystemEventTypeDEKRotationCompleted,
		},
		fixture.auditEventTypes(utCtx, t),
	)

	// Rotating again works from the state the first one left behind
	assert.Nil(fixture.uut.RotateEncryptionKey(utCtx))
	fixture.assertValuesReadable(utCtx, t, values)
}

// TestMaintenanceRotateEncryptionKeyResume verifies that a rotation interrupted after the
// key swap resumes at the drain, rather than swapping keys a second time.
//
// Without the entry dispatch the rerun would retire the new key and mint a third, leaving
// data spread across keys and a rotation which never converges.
func TestMaintenanceRotateEncryptionKeyResume(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newTestFixture(utCtx, t, "self-signed", 2)
	assert.Nil(fixture.uut.Initialize(utCtx))

	values := map[string][]byte{
		"alpha": []byte("one"), "bravo": []byte("two"), "charlie": []byte("three"),
	}
	fixture.writeValues(utCtx, t, values)

	originalKey := fixture.encryptionKeys(utCtx, t)[0]

	// Stage a crash between steps (b) and (c): the rotation is open, the old key is retired
	// and its replacement exists, but no version has moved
	var replacementKey models.EncryptionKey
	assert.Nil(fixture.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			if err := dbClient.MarkSystemRotatingDEK(ctx); err != nil {
				return err
			}
			if err := dbClient.MarkEncryptionKeyRetired(ctx, originalKey.ID); err != nil {
				return err
			}
			var err error
			replacementKey, err = fixture.engine.NewEncryptionKey(ctx, dbClient)
			return err
		},
	))
	assert.Len(fixture.encryptionKeys(utCtx, t), 2)

	assert.Nil(fixture.uut.RotateEncryptionKey(utCtx))

	// The rerun finished the interrupted rotation instead of starting another one
	keys := fixture.encryptionKeys(utCtx, t)
	assert.Len(keys, 1)
	assert.Equal(replacementKey.ID, keys[0].ID)
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))

	for _, version := range fixture.recordVersions(utCtx, t) {
		assert.Equal(replacementKey.ID, version.EncKeyID)
	}
	fixture.assertValuesReadable(utCtx, t, values)
}

// TestMaintenanceRotateEncryptionKeyResumeBeforeKeySwap verifies that a rotation
// interrupted after the barrier but before the key swap starts at the swap.
func TestMaintenanceRotateEncryptionKeyResumeBeforeKeySwap(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newTestFixture(utCtx, t, "self-signed", 0)
	assert.Nil(fixture.uut.Initialize(utCtx))

	values := map[string][]byte{"alpha": []byte("one")}
	fixture.writeValues(utCtx, t, values)
	originalKey := fixture.encryptionKeys(utCtx, t)[0]

	// Stage a crash between steps (a) and (b): the rotation is open, but no key was retired
	assert.Nil(fixture.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.MarkSystemRotatingDEK(ctx)
		},
	))

	assert.Nil(fixture.uut.RotateEncryptionKey(utCtx))

	keys := fixture.encryptionKeys(utCtx, t)
	assert.Len(keys, 1)
	assert.NotEqual(originalKey.ID, keys[0].ID)
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))
	fixture.assertValuesReadable(utCtx, t, values)
}

// TestMaintenanceRotateEncryptionKeyBlocked verifies the whole of the undecryptable version
// recovery path: a corrupted row halts the rotation, leaves the system blocked, is reported
// by the diagnostic, is destroyed by the purge, and the rerun then completes.
func TestMaintenanceRotateEncryptionKeyBlocked(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newTestFixture(utCtx, t, "self-signed", 2)
	assert.Nil(fixture.uut.Initialize(utCtx))

	values := map[string][]byte{
		"alpha": []byte("one"), "bravo": []byte("two"),
		"charlie": []byte("three"), "delta": []byte("four"), "echo": []byte("five"),
	}
	fixture.writeValues(utCtx, t, values)

	originalKey := fixture.encryptionKeys(utCtx, t)[0]

	// Something tampered with one version's cipher text
	var corrupted models.RecordVersion
	assert.Nil(fixture.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			record, err := dbClient.GetRecordByName(ctx, "charlie")
			if err != nil {
				return err
			}
			versions, err := dbClient.ListVersionsOfOneRecord(
				ctx, record, db.RecordVersionQueryFilter{},
			)
			if err != nil {
				return err
			}
			corrupted = versions[0]

			tampered := make([]byte, len(corrupted.EncValue))
			copy(tampered, corrupted.EncValue)
			tampered[0] ^= 0xff

			_, err = dbClient.UpdateRecordVersionEncryption(
				ctx, corrupted.ID, originalKey, tampered, corrupted.EncNonce,
			)
			return err
		},
	))

	// The rotation refuses to report success over data it could not move
	halted := fixture.uut.RotateEncryptionKey(utCtx)
	assert.Error(halted)
	assert.Equal(models.SystemStateDEKRotating, fixture.systemState(utCtx, t))

	// The failure presents as a maintenance failure
	var maintenanceErr models.MaintenanceError
	assert.True(errors.As(halted, &maintenanceErr))

	// And still names the row which blocked it. Recovering from this depends on the caller
	// being able to tell a corrupted row from a failed write, so the outermost wrap must not
	// bury the finding underneath it.
	var blocked encryption.UndecryptableVersion
	assert.True(errors.As(halted, &blocked))
	assert.Equal(corrupted.ID, blocked.Version.ID)

	// The retired key is still there, still holding the row nothing could convert
	keys := fixture.encryptionKeys(utCtx, t)
	assert.Len(keys, 2)

	// A KV store can't even be opened while the system is blocked, so the embedding
	// application learns of this at startup rather than at some later write
	fixture.assertStoreRefused(utCtx, t)

	// The diagnostic names exactly the damaged row, and destroys nothing
	findings, err := fixture.uut.ListUndecryptableVersions(utCtx)
	assert.Nil(err)
	assert.Len(findings, 1)
	assert.Equal(corrupted.ID, findings[0].Version.ID)
	assert.Equal("charlie", findings[0].RecordName)
	assert.Error(findings[0].Cause)
	assert.Len(fixture.recordVersions(utCtx, t), len(values))

	// Destroying it is a separate, audited act
	purged, err := fixture.uut.PurgeUndecryptableVersions(utCtx)
	assert.Nil(err)
	assert.Len(purged, 1)
	assert.Equal(corrupted.ID, purged[0].Version.ID)
	assert.Equal("charlie", purged[0].RecordName)
	assert.Len(fixture.recordVersions(utCtx, t), len(values)-1)
	assert.Contains(fixture.auditEventTypes(utCtx, t), models.SystemEventTypePurgeRecordVersion)

	// Nothing is left to block it, so the rerun resumes the drain and completes
	assert.Nil(fixture.uut.RotateEncryptionKey(utCtx))
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))
	assert.Len(fixture.encryptionKeys(utCtx, t), 1)

	// Everything which was not destroyed survived the rotation
	delete(values, "charlie")
	fixture.assertValuesReadable(utCtx, t, values)
}

// TestMaintenanceRotateEncryptionKeyRefusesBrokenInvariant verifies that a rotation refuses
// to run against a system which does not hold exactly one active encryption key.
//
// DESIGN §5.2 makes that the definition of READY, and the rotation is built on it: the drain
// moves data onto "the" new key and the close deletes "the" retired ones. A system which
// violates the invariant has a problem a rotation cannot fix, and starting one would spread
// the data across more keys rather than converge it onto one.
func TestMaintenanceRotateEncryptionKeyRefusesBrokenInvariant(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// READY, but nothing ever minted a key, so nothing can encrypt
	{
		fixture := newTestFixture(utCtx, t, "self-signed", 0)
		assert.Nil(fixture.persistence.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				return dbClient.MarkSystemReady(ctx)
			},
		))

		err := fixture.uut.RotateEncryptionKey(utCtx)
		assert.ErrorContains(err, "holds 0 active encryption keys")

		var maintenanceErr models.MaintenanceError
		assert.True(errors.As(err, &maintenanceErr))
	}

	// READY, but a second key encrypts alongside the first
	{
		fixture := newTestFixture(utCtx, t, "self-signed", 0)
		assert.Nil(fixture.uut.Initialize(utCtx))
		assert.Nil(fixture.persistence.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				_, err := fixture.engine.NewEncryptionKey(ctx, dbClient)
				return err
			},
		))
		assert.Len(fixture.encryptionKeys(utCtx, t), 2)

		assert.ErrorContains(
			fixture.uut.RotateEncryptionKey(utCtx), "holds 2 active encryption keys",
		)
	}

	// Mid rotation, with the old key retired but no replacement to move the data onto
	{
		fixture := newTestFixture(utCtx, t, "self-signed", 0)
		assert.Nil(fixture.uut.Initialize(utCtx))
		active := fixture.encryptionKeys(utCtx, t)[0]

		assert.Nil(fixture.persistence.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				if err := dbClient.MarkSystemRotatingDEK(ctx); err != nil {
					return err
				}
				return dbClient.MarkEncryptionKeyRetired(ctx, active.ID)
			},
		))

		// The resume dispatch takes the active key as the replacement, so there being none is
		// a different failure from there being none at the start
		assert.ErrorContains(
			fixture.uut.RotateEncryptionKey(utCtx),
			"an interrupted rotation left 0 active encryption keys",
		)
		assert.Equal(models.SystemStateDEKRotating, fixture.systemState(utCtx, t))
	}
}
