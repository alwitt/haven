package db_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/logger"
)

// TestDBEncryptionKeyRecord verifies the behaviour of the encryption key API:
//   - RecordEncryptionKey
//   - GetEncryptionKey
//   - DeleteEncryptionKey
//
// The test performs the following steps:
//
//  1. Record two encryption keys (test key 1 and test key 2).
//  2. Retrieve each key and verify the stored material.
//  3. Delete test key 1 and confirm that it can no longer be retrieved.
//  4. Confirm that test key 2 still exists.
//  5. List audit events – there should be three events:
//     • NewEncryptionKey for test key 1
//     • NewEncryptionKey for test key 2
//     • DeleteEncryptionKey for test key 1
func TestDBEncryptionKeyRecord(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// Create a unique temporary DB file for this test
	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	uut, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)

	// Create database tables
	assert.Nil(uut.RunSQLInTransaction(utCtx, db.DefineTables))

	// 1. Record test key 1
	var key1 models.EncryptionKey
	keyMaterial1 := []byte(uuid.NewString())
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, keyMaterial1)
		if err != nil {
			return err
		}
		key1 = ek
		return nil
	})
	assert.Nil(err)

	// 2. Retrieve test key 1 and verify content
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key1.ID)
		if err != nil {
			return err
		}
		assert.Equal(keyMaterial1, ek.EncKeyMaterial)
		return nil
	})
	assert.Nil(err)

	// 3. Record test key 2
	var key2 models.EncryptionKey
	keyMaterial2 := []byte(uuid.NewString())
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, keyMaterial2)
		if err != nil {
			return err
		}
		key2 = ek
		return nil
	})
	assert.Nil(err)

	// 4. Retrieve test key 2 and verify content
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key2.ID)
		if err != nil {
			return err
		}
		assert.Equal(keyMaterial2, ek.EncKeyMaterial)
		return nil
	})
	assert.Nil(err)

	// 5. Delete test key 1
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.DeleteEncryptionKey(ctx, key1.ID)
	})
	assert.Nil(err)

	// 6. Attempt to retrieve deleted key 1 – should fail
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		_, err := dbClient.GetEncryptionKey(ctx, key1.ID)
		return err
	})
	assert.Error(err)

	// 7. Retrieve test key 2 again to ensure it still exists
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key2.ID)
		if err != nil {
			return err
		}
		assert.Equal(keyMaterial2, ek.EncKeyMaterial)
		return nil
	})
	assert.Nil(err)

	// 8. List audit events – there should be three
	var events []models.SystemEventAudit
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		events, err = dbClient.ListSystemEvents(ctx, db.SystemEventQueryFilter{})
		return err
	})
	assert.Nil(err)
	assert.Len(events, 3)

	validate := validator.New()
	assert.Nil(models.RegisterWithValidator(validate))

	// 9. Verify event types: two new keys, one delete
	newKey1Event := false
	newKey2Event := false
	delKey1Event := false
	for _, e := range events {
		metadata, err := e.ParseMetadata(validate)
		assert.Nil(err)
		encMetadata, ok := metadata.(models.SystemEventEncKeyRelated)
		assert.True(ok)
		switch e.EventType {
		case models.SystemEventTypeNewEncryptionKey:
			switch encMetadata.KeyID {
			case key1.ID:
				newKey1Event = true
			case key2.ID:
				newKey2Event = true
			}

		case models.SystemEventTypeDeleteEncryptionKey:
			if encMetadata.KeyID == key1.ID {
				delKey1Event = true
			}
		}
	}
	assert.True(newKey1Event)
	assert.True(newKey2Event)
	assert.True(delKey1Event)
}

// TestDBEncryptionKeyStateChange verifies the behaviour of the encryption key state
// change API (MarkEncryptionKeyActive / MarkEncryptionKeyInactive).
//
// The test performs the following steps:
//
//  1. Record a new encryption key (test key 1).
//  2. Read back test key 1 and verify its content and that it is active.
//  3. Mark test key 1 as inactive.
//  4. Read back test key 1 and verify it is inactive.
//  5. Mark test key 1 as active again.
//  6. Read back test key 1 and verify it is active.
//  7. Mark test key 1 as active once more (no state change, no audit event).
//  8. Read back test key 1 and verify it remains active.
//  9. List system audit events – there should be 3 events:
//     • NewEncryptionKey for test key 1
//     • DeactivateEncryptionKey for test key 1
//     • ActivateEncryptionKey for test key 1
func TestDBEncryptionKeyStateChange(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// Create a unique temporary DB file for this test
	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	uut, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)

	// Create database tables
	assert.Nil(uut.RunSQLInTransaction(utCtx, db.DefineTables))

	// 1. Record test key 1
	var key1 models.EncryptionKey
	keyMaterial1 := []byte(uuid.NewString())
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, keyMaterial1)
		if err != nil {
			return err
		}
		key1 = ek
		return nil
	})
	assert.Nil(err)

	// 2. Retrieve test key 1 and verify content and active state
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key1.ID)
		if err != nil {
			return err
		}
		assert.Equal(keyMaterial1, ek.EncKeyMaterial)
		assert.Equal(models.EncryptionKeyStateActive, ek.State)
		return nil
	})
	assert.Nil(err)

	// 3. Mark test key 1 as inactive
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkEncryptionKeyInactive(ctx, key1.ID)
	})
	assert.Nil(err)

	// 4. Retrieve test key 1 and verify it is inactive
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key1.ID)
		if err != nil {
			return err
		}
		assert.Equal(models.EncryptionKeyStateInactive, ek.State)
		return nil
	})
	assert.Nil(err)

	// 5. Mark test key 1 as active
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkEncryptionKeyActive(ctx, key1.ID)
	})
	assert.Nil(err)

	// 6. Retrieve test key 1 and verify it is active
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key1.ID)
		if err != nil {
			return err
		}
		assert.Equal(models.EncryptionKeyStateActive, ek.State)
		return nil
	})
	assert.Nil(err)

	// 7. Mark test key 1 as active again (no state change)
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkEncryptionKeyActive(ctx, key1.ID)
	})
	assert.Nil(err)

	// 8. Retrieve test key 1 and verify it is still active
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key1.ID)
		if err != nil {
			return err
		}
		assert.Equal(models.EncryptionKeyStateActive, ek.State)
		return nil
	})
	assert.Nil(err)

	// 9. List audit events – there should be 3 events
	var events []models.SystemEventAudit
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		events, err = dbClient.ListSystemEvents(ctx, db.SystemEventQueryFilter{})
		return err
	})
	assert.Nil(err)

	validate := validator.New()
	assert.Nil(models.RegisterWithValidator(validate))
	assert.Len(events, 3)

	newKeyEvent := false
	deactivateEvent := false
	activateEvent := false
	for _, e := range events {
		metadata, err := e.ParseMetadata(validate)
		assert.Nil(err)
		encMeta, ok := metadata.(models.SystemEventEncKeyRelated)
		assert.True(ok)
		switch e.EventType {
		case models.SystemEventTypeNewEncryptionKey:
			if encMeta.KeyID == key1.ID {
				newKeyEvent = true
			}
		case models.SystemEventTypeDeactivateEncryptionKey:
			if encMeta.KeyID == key1.ID {
				deactivateEvent = true
			}
		case models.SystemEventTypeActivateEncryptionKey:
			if encMeta.KeyID == key1.ID {
				activateEvent = true
			}
		}
	}
	assert.True(newKeyEvent)
	assert.True(deactivateEvent)
	assert.True(activateEvent)
}

// TestDBEncryptionKeyListing verifies the behaviour of the encryption key
// listing API together with the state transition helpers.
//
// The test performs the following steps:
//
//  1. Record three encryption keys (test key 1, test key 2, test key 3).
//  2. Verify that each key is stored correctly and is ACTIVE.
//  3. Mark test key 3 as INACTIVE.
//  4. List all encryption keys – there should be three keys.
//  5. List only ACTIVE keys – there should be two keys (test key 1 and test key 2).
//  6. List only INACTIVE keys – there should be one key (test key 3).
//  7. List system audit events – there should be four events:
//     • NewEncryptionKey for test key 1
//     • NewEncryptionKey for test key 2
//     • NewEncryptionKey for test key 3
//     • DeactivateEncryptionKey for test key 3
func TestDBEncryptionKeyListing(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// Create a unique temporary DB file for this test
	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	uut, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)

	// Create database tables
	assert.Nil(uut.RunSQLInTransaction(utCtx, db.DefineTables))

	// ------------------------------------------------------------------
	// 1 – Record test key 1
	var key1 models.EncryptionKey
	keyMaterial1 := []byte(uuid.NewString())
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, keyMaterial1)
		if err != nil {
			return err
		}
		key1 = ek
		return nil
	})
	assert.Nil(err)

	// 2 – Verify key 1 content and ACTIVE state
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key1.ID)
		if err != nil {
			return err
		}
		assert.Equal(keyMaterial1, ek.EncKeyMaterial)
		assert.Equal(models.EncryptionKeyStateActive, ek.State)
		return nil
	})
	assert.Nil(err)

	// ------------------------------------------------------------------
	// 3 – Record test key 2
	var key2 models.EncryptionKey
	keyMaterial2 := []byte(uuid.NewString())
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, keyMaterial2)
		if err != nil {
			return err
		}
		key2 = ek
		return nil
	})
	assert.Nil(err)

	// 4 – Verify key 2 content and ACTIVE state
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key2.ID)
		if err != nil {
			return err
		}
		assert.Equal(keyMaterial2, ek.EncKeyMaterial)
		assert.Equal(models.EncryptionKeyStateActive, ek.State)
		return nil
	})
	assert.Nil(err)

	// ------------------------------------------------------------------
	// 5 – Record test key 3
	var key3 models.EncryptionKey
	keyMaterial3 := []byte(uuid.NewString())
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, keyMaterial3)
		if err != nil {
			return err
		}
		key3 = ek
		return nil
	})
	assert.Nil(err)

	// 6 – Verify key 3 content and ACTIVE state
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.GetEncryptionKey(ctx, key3.ID)
		if err != nil {
			return err
		}
		assert.Equal(keyMaterial3, ek.EncKeyMaterial)
		assert.Equal(models.EncryptionKeyStateActive, ek.State)
		return nil
	})
	assert.Nil(err)

	// ------------------------------------------------------------------
	// 7 – Mark test key 3 as INACTIVE
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkEncryptionKeyInactive(ctx, key3.ID)
	})
	assert.Nil(err)

	// ------------------------------------------------------------------
	// 8 – List all encryption keys – expect three
	var allKeys []models.EncryptionKey
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		allKeys, err = dbClient.ListEncryptionKeys(ctx, db.EncryptionKeyQueryFilter{})
		return err
	})
	assert.Nil(err)
	assert.Len(allKeys, 3)

	// Build a map from key ID to key for quick lookup
	keyMap := make(map[string]models.EncryptionKey, len(allKeys))
	for _, k := range allKeys {
		keyMap[k.ID] = k
	}
	// Verify that each key is present with the expected material
	assert.Equal(keyMaterial1, keyMap[key1.ID].EncKeyMaterial)
	assert.Equal(keyMaterial2, keyMap[key2.ID].EncKeyMaterial)
	assert.Equal(keyMaterial3, keyMap[key3.ID].EncKeyMaterial)

	// ------------------------------------------------------------------
	// 9 – List only ACTIVE keys – expect two (key1, key2)
	var activeKeys []models.EncryptionKey
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		activeKeys, err = dbClient.ListEncryptionKeys(
			ctx,
			db.EncryptionKeyQueryFilter{
				TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateActive},
			},
		)
		return err
	})
	assert.Nil(err)
	assert.Len(activeKeys, 2)

	// Check that the active keys are key1 and key2
	activeIDs := map[string]bool{activeKeys[0].ID: true, activeKeys[1].ID: true}
	assert.True(activeIDs[key1.ID])
	assert.True(activeIDs[key2.ID])
	assert.False(activeIDs[key3.ID])

	// ------------------------------------------------------------------
	// 10 – List only INACTIVE keys – expect one (key3)
	var inactiveKeys []models.EncryptionKey
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		inactiveKeys, err = dbClient.ListEncryptionKeys(
			ctx,
			db.EncryptionKeyQueryFilter{
				TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateInactive},
			},
		)
		return err
	})
	assert.Nil(err)
	assert.Len(inactiveKeys, 1)
	assert.Equal(key3.ID, inactiveKeys[0].ID)

	// ------------------------------------------------------------------
	// 11 – List system audit events – expect four
	var events []models.SystemEventAudit
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		events, err = dbClient.ListSystemEvents(ctx, db.SystemEventQueryFilter{})
		return err
	})
	assert.Nil(err)
	assert.Len(events, 4)

	validate := validator.New()
	assert.Nil(models.RegisterWithValidator(validate))

	// Count events by type and verify metadata
	newKeyEvents := 0
	deactivateEvents := 0
	for _, e := range events {
		meta, err := e.ParseMetadata(validate)
		assert.Nil(err)
		encMeta, ok := meta.(models.SystemEventEncKeyRelated)
		assert.True(ok)

		switch e.EventType {
		case models.SystemEventTypeNewEncryptionKey:
			newKeyEvents++
			// Each NewEncryptionKey should reference one of the three keys
			assert.Contains([]string{key1.ID, key2.ID, key3.ID}, encMeta.KeyID)
		case models.SystemEventTypeDeactivateEncryptionKey:
			deactivateEvents++
			assert.Equal(key3.ID, encMeta.KeyID)
		}
	}

	assert.Equal(3, newKeyEvents)
	assert.Equal(1, deactivateEvents)
}
