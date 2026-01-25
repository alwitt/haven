package db_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/logger"
)

func TestDBSystemParameterInit(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	uut, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)

	assert.Nil(uut.RunSQLInTransaction(utCtx, db.DefineTables))

	// Read system parameters
	assert.Nil(
		uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				params, err := dbClient.GetSystemParamEntry(ctx)
				assert.Nil(err)
				assert.Equal(db.GlobalSystemParamEntryID, params.ID)
				assert.Equal(models.SystemStatePreInit, params.State)
				return err
			},
		),
	)

	// Read again
	assert.Nil(
		uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				params, err := dbClient.GetSystemParamEntry(ctx)
				assert.Nil(err)
				assert.Equal(db.GlobalSystemParamEntryID, params.ID)
				assert.Equal(models.SystemStatePreInit, params.State)
				return err
			},
		),
	)
}

// TestDBSystemParameterTestStateChange verifies the state transition behaviour
// of the system parameters (pre‑init → initializing → running) and the
// corresponding audit events.
func TestDBSystemParameterTestStateChange(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// A unique temporary DB file for this test
	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	uut, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)

	// Create tables
	assert.Nil(uut.RunSQLInTransaction(utCtx, db.DefineTables))

	// 1. Verify initial state is PRE_INITIALIZATION
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		params, err := dbClient.GetSystemParamEntry(ctx)
		assert.Nil(err)
		assert.Equal(models.SystemStatePreInit, params.State)
		return err
	})
	assert.Nil(err)

	// 2. Mark system as initializing
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkSystemInitializing(ctx)
	})
	assert.Nil(err)

	// 3. Verify state is INITIALIZING
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		params, err := dbClient.GetSystemParamEntry(ctx)
		assert.Nil(err)
		assert.Equal(models.SystemStateInit, params.State)
		return err
	})
	assert.Nil(err)

	// 4. Mark system as initializing again (idempotent)
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkSystemInitializing(ctx)
	})
	assert.Nil(err)

	// 5. Verify state remains INITIALIZING
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		params, err := dbClient.GetSystemParamEntry(ctx)
		assert.Nil(err)
		assert.Equal(models.SystemStateInit, params.State)
		return err
	})
	assert.Nil(err)

	// 6. Mark system as initialized
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkSystemInitialized(ctx)
	})
	assert.Nil(err)

	// 7. Verify state is RUNNING
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		params, err := dbClient.GetSystemParamEntry(ctx)
		assert.Nil(err)
		assert.Equal(models.SystemStateRunning, params.State)
		return err
	})
	assert.Nil(err)

	// 8. Mark system as initialized again (idempotent)
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkSystemInitialized(ctx)
	})
	assert.Nil(err)

	// 9. Verify state remains RUNNING
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		params, err := dbClient.GetSystemParamEntry(ctx)
		assert.Nil(err)
		assert.Equal(models.SystemStateRunning, params.State)
		return err
	})
	assert.Nil(err)

	// 10. Attempt to mark system initializing again should fail
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkSystemInitializing(ctx)
	})
	assert.Error(err)

	// 11. List audit events – there should be exactly two
	var events []models.SystemEventAudit
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		filters := db.SystemEventQueryFilter{}
		events, err = dbClient.ListSystemEvents(ctx, filters)
		return err
	})
	assert.Nil(err)
	assert.Len(events, 2)

	// 12. Verify the event types
	hasInitializing := false
	hasInitialized := false
	for _, e := range events {
		if e.EventType == models.SystemEventTypeInitializing {
			hasInitializing = true
		}
		if e.EventType == models.SystemEventTypeInitialized {
			hasInitialized = true
		}
	}
	assert.True(hasInitializing, "expected initializing event")
	assert.True(hasInitialized, "expected initialized event")
}
