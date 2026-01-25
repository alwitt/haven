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

// TestDBCreateDataRecord verifies the behavior of `Database.DefineNewRecord`,
// `Database.GetRecord`, and `Database.DeleteRecord`.
func TestDBCreateDataRecord(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// Create a unique temporary DB file for this test
	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	// Create a new DB connection
	uut, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)

	// Create database tables
	assert.Nil(uut.RunSQLInTransaction(utCtx, db.DefineTables))

	// -------------------------------------------------------------------------
	// 1 – Define a new data record (test record 1)
	var rec1 models.Record
	rec1Name := uuid.NewString()
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec1Name)
		if err != nil {
			return err
		}
		rec1 = r
		return nil
	})
	assert.Nil(err)

	// 2 – Get back test record 1 and verify its content
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.GetRecord(ctx, rec1.ID)
		if err != nil {
			return err
		}
		assert.Equal(rec1Name, r.Name)
		return nil
	})
	assert.Nil(err)

	// -------------------------------------------------------------------------
	// 3 – Define a new data record (test record 2)
	var rec2 models.Record
	rec2Name := uuid.NewString()
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec2Name)
		if err != nil {
			return err
		}
		rec2 = r
		return nil
	})
	assert.Nil(err)

	// 4 – Get back test record 2 and verify its content
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.GetRecord(ctx, rec2.ID)
		if err != nil {
			return err
		}
		assert.Equal(rec2Name, r.Name)
		return nil
	})
	assert.Nil(err)

	// -------------------------------------------------------------------------
	// 5 – Define a new data record using the same name as test record 1 (should fail)
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		_, err := dbClient.DefineNewRecord(ctx, rec1Name)
		return err
	})
	assert.Error(err) // duplicate name should trigger an error

	// -------------------------------------------------------------------------
	// 6 – Delete test record 1
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.DeleteRecord(ctx, rec1.ID)
	})
	assert.Nil(err)

	// 7 – Get back test record 1 (should fail)
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		_, err := dbClient.GetRecord(ctx, rec1.ID)
		return err
	})
	assert.Error(err)

	// -------------------------------------------------------------------------
	// 8 – Define a new data record using the same name as test record 1 (test record 3)
	var rec3 models.Record
	rec3Name := rec1Name
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec3Name)
		if err != nil {
			return err
		}
		rec3 = r
		return nil
	})
	assert.Nil(err)

	// 9 – Get back test record 3 and verify its content
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.GetRecord(ctx, rec3.ID)
		if err != nil {
			return err
		}
		assert.Equal(rec3Name, r.Name)
		return nil
	})
	assert.Nil(err)

	// -------------------------------------------------------------------------
	// 10 – List system audit events
	var events []models.SystemEventAudit
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		events, err = dbClient.ListSystemEvents(ctx, db.SystemEventQueryFilter{})
		return err
	})
	assert.Nil(err)

	// There should be 4 events
	assert.Len(events, 4)

	// Register validator for metadata parsing
	validate := validator.New()
	assert.Nil(models.RegisterWithValidator(validate))

	// Count event types and verify metadata
	createEvents := map[string]string{}
	deleteEvents := 0
	for _, e := range events {
		meta, err := e.ParseMetadata(validate)
		assert.Nil(err)
		encMeta, ok := meta.(models.SystemEventDataRecordRelated)
		assert.True(ok)

		switch e.EventType {
		case models.SystemEventTypeAddNewRecord:
			assert.Contains([]string{rec1.ID, rec2.ID, rec3.ID}, encMeta.RecordID)
			if encMeta.RecordID == rec1.ID {
				assert.Equal(rec1Name, encMeta.RecordName)
				createEvents[rec1.ID] = rec1Name
			}
			if encMeta.RecordID == rec2.ID {
				assert.Equal(rec2Name, encMeta.RecordName)
				createEvents[rec2.ID] = rec2Name
			}
			if encMeta.RecordID == rec3.ID {
				assert.Equal(rec3Name, encMeta.RecordName)
				createEvents[rec3.ID] = rec3Name
			}
		case models.SystemEventTypeDeleteRecord:
			deleteEvents++
			assert.Equal(rec1.ID, encMeta.RecordID)
			assert.Equal(rec1Name, encMeta.RecordName)
		}
	}

	assert.Equal(3, len(createEvents))
	assert.Equal(1, deleteEvents)
}

// TestDBFindRecordByName verifies the behavior of Database.GetRecordByName.
func TestDBFindRecordByName(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// Create a unique temporary DB file for this test
	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	// Create a new DB connection
	uut, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)

	// Create database tables
	assert.Nil(uut.RunSQLInTransaction(utCtx, db.DefineTables))

	// ---------- Create test record 1 ----------
	var rec1 models.Record
	rec1Name := uuid.NewString()
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec1Name)
		if err != nil {
			return err
		}
		rec1 = r
		return nil
	})
	assert.Nil(err)

	// Verify GetRecord by ID for record 1
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.GetRecord(ctx, rec1.ID)
		if err != nil {
			return err
		}
		assert.Equal(rec1Name, r.Name)
		return nil
	})
	assert.Nil(err)

	// ---------- Create test record 2 ----------
	var rec2 models.Record
	rec2Name := uuid.NewString()
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec2Name)
		if err != nil {
			return err
		}
		rec2 = r
		return nil
	})
	assert.Nil(err)

	// Verify GetRecord by ID for record 2
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.GetRecord(ctx, rec2.ID)
		if err != nil {
			return err
		}
		assert.Equal(rec2Name, r.Name)
		return nil
	})
	assert.Nil(err)

	// ---------- Fetch record 1 by name ----------
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.GetRecordByName(ctx, rec1Name)
		if err != nil {
			return err
		}
		assert.Equal(rec1.ID, r.ID)
		assert.Equal(rec1Name, r.Name)
		return nil
	})
	assert.Nil(err)

	// ---------- Fetch record 2 by name ----------
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.GetRecordByName(ctx, rec2Name)
		if err != nil {
			return err
		}
		assert.Equal(rec2.ID, r.ID)
		assert.Equal(rec2Name, r.Name)
		return nil
	})
	assert.Nil(err)
}

// TestDBListRecords – verifies that Database.ListRecords correctly returns
// all records that have been created.
func TestDBListRecords(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	// Create a unique temporary DB file for this test
	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	// Create a new DB connection
	uut, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)

	// Create database tables
	assert.Nil(uut.RunSQLInTransaction(utCtx, db.DefineTables))

	// -------------------------------------------------------------------------
	// 1 – Define three new data records
	// -------------------------------------------------------------------------
	var (
		rec1, rec2, rec3 models.Record
	)
	rec1Name := uuid.NewString()
	rec2Name := uuid.NewString()
	rec3Name := uuid.NewString()

	// Record 1
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec1Name)
		if err != nil {
			return err
		}
		rec1 = r
		return nil
	})
	assert.Nil(err)

	// Record 2
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec2Name)
		if err != nil {
			return err
		}
		rec2 = r
		return nil
	})
	assert.Nil(err)

	// Record 3
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec3Name)
		if err != nil {
			return err
		}
		rec3 = r
		return nil
	})
	assert.Nil(err)

	// -------------------------------------------------------------------------
	// 2 – List all data records
	// -------------------------------------------------------------------------
	var records []models.Record
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		records, err = dbClient.ListRecords(ctx, db.RecordQueryFilter{})
		return err
	})
	assert.Nil(err)

	// There should be exactly three records
	assert.Len(records, 3)

	// Build a map of ID -> Name for easier verification
	nameMap := map[string]string{}
	for _, r := range records {
		nameMap[r.ID] = r.Name
	}

	// Verify that each expected record is present with the correct name
	assert.Equal(rec1Name, nameMap[rec1.ID])
	assert.Equal(rec2Name, nameMap[rec2.ID])
	assert.Equal(rec3Name, nameMap[rec3.ID])
}
