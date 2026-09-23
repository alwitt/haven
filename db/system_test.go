package db_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/logger"
)

// testKekID stands in for the ID of a primary RSA key pair
const testKekID = "0f9a1c7b3e5d2846a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071"

// newTestDBClient prepare a persistence client against a fresh SQLite database
func newTestDBClient(utCtx context.Context, t *testing.T) db.Client {
	assert := assert.New(t)

	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	uut, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)
	assert.Nil(uut.RunSQLInTransaction(utCtx, db.DefineTables))

	return uut
}

// readSystemState helper to read the current system state
func readSystemState(
	utCtx context.Context, t *testing.T, uut db.Client,
) models.SystemStateENUMType {
	assert := assert.New(t)

	var state models.SystemStateENUMType
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			params, err := dbClient.GetSystemParamEntry(ctx)
			state = params.State
			return err
		},
	))

	return state
}

// newTestValidator prepare a validator able to parse system event metadata
func newTestValidator(t *testing.T) *validator.Validate {
	instance := validator.New()
	assert.New(t).Nil(models.RegisterWithValidator(instance))
	return instance
}

// markSystemReady drive a fresh system into READY, so the record data API is open
func markSystemReady(utCtx context.Context, t *testing.T, uut db.Client) {
	assert := assert.New(t)
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.MarkSystemReady(ctx)
		},
	))
}

func TestDBSystemParameterInit(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut := newTestDBClient(utCtx, t)

	// The singleton entry is defined on first read, in PRE_INITIALIZATION
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

	// Reading again returns the same entry, not a second one
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

// TestDBSystemParameterStateChange walks the system lifecycle through every legal edge,
// and verifies that each one is recorded as the expected audit event.
func TestDBSystemParameterStateChange(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut := newTestDBClient(utCtx, t)

	transition := func(
		change func(ctx context.Context, dbClient db.Database) error,
	) error {
		return uut.UseDatabaseInTransaction(utCtx, change)
	}
	toReady := func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkSystemReady(ctx)
	}
	toDEKRotating := func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkSystemRotatingDEK(ctx)
	}
	toKEKRotating := func(ctx context.Context, dbClient db.Database) error {
		return dbClient.MarkSystemRotatingKEK(ctx)
	}

	assert.Equal(models.SystemStatePreInit, readSystemState(utCtx, t, uut))

	// PRE_INITIALIZATION -> READY
	assert.Nil(transition(toReady))
	assert.Equal(models.SystemStateReady, readSystemState(utCtx, t, uut))

	// Repeating a transition already made is a NOOP, not an error
	assert.Nil(transition(toReady))
	assert.Equal(models.SystemStateReady, readSystemState(utCtx, t, uut))

	// READY -> DEK_ROTATION_IN_PROGRESS -> READY
	assert.Nil(transition(toDEKRotating))
	assert.Equal(models.SystemStateDEKRotating, readSystemState(utCtx, t, uut))
	assert.Nil(transition(toDEKRotating))
	assert.Nil(transition(toReady))
	assert.Equal(models.SystemStateReady, readSystemState(utCtx, t, uut))

	// READY -> KEK_ROTATION_IN_PROGRESS -> READY
	assert.Nil(transition(toKEKRotating))
	assert.Equal(models.SystemStateKEKRotating, readSystemState(utCtx, t, uut))
	assert.Nil(transition(toReady))
	assert.Equal(models.SystemStateReady, readSystemState(utCtx, t, uut))

	// One rotation can't hand straight over to the other
	assert.Nil(transition(toDEKRotating))
	assert.Error(transition(toKEKRotating))
	assert.Equal(models.SystemStateDEKRotating, readSystemState(utCtx, t, uut))
	assert.Nil(transition(toReady))

	// Every transition is audited, in the order it happened
	var events []models.SystemEventAudit
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			events, err = dbClient.ListSystemEvents(ctx, db.SystemEventQueryFilter{})
			return err
		},
	))

	eventTypes := []models.SystemEventTypeENUMType{}
	for _, entry := range events {
		eventTypes = append(eventTypes, entry.EventType)
	}
	assert.Equal(
		[]models.SystemEventTypeENUMType{
			models.SystemEventTypeInitialized,
			models.SystemEventTypeDEKRotationStarted,
			models.SystemEventTypeDEKRotationCompleted,
			models.SystemEventTypeKEKRotationStarted,
			models.SystemEventTypeKEKRotationCompleted,
			models.SystemEventTypeDEKRotationStarted,
			models.SystemEventTypeDEKRotationCompleted,
		},
		eventTypes,
	)
}

// TestDBSystemParameterIllegalStateChange verifies that transitions outside the state
// graph are refused, and leave the recorded state untouched.
func TestDBSystemParameterIllegalStateChange(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut := newTestDBClient(utCtx, t)

	// A rotation can't start before the system has ever been initialized
	assert.Error(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.MarkSystemRotatingDEK(ctx)
		},
	))
	assert.Equal(models.SystemStatePreInit, readSystemState(utCtx, t, uut))

	assert.Error(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.MarkSystemRotatingKEK(ctx)
		},
	))
	assert.Equal(models.SystemStatePreInit, readSystemState(utCtx, t, uut))

	// A refused transition records no audit event
	var events []models.SystemEventAudit
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			events, err = dbClient.ListSystemEvents(ctx, db.SystemEventQueryFilter{})
			return err
		},
	))
	assert.Empty(events)
}
