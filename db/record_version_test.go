package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/logger"
)

// TestDBCreateDataRecordVersion verifies the behavior of `Database.DefineNewVersionForRecord`.
//
// The test performs the following steps:
//
//   - Define a new data record, `test record 1`.
//   - Define a new encryption key, `test key 1`.
//   - Define a new data record version for `test record 1` using `test key 1` (test version 1).
//   - Get back test version 1 and verify its content.
//   - Define a new data record version for `test record 1` using `test key 1` (test version 2).
//   - Get back test version 2 and verify its content.
func TestDBCreateDataRecordVersion(t *testing.T) {
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

	// The record data API is closed outside the READY state
	markSystemReady(utCtx, t, uut)

	// --------------------------------------------------
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

	// --------------------------------------------------
	// 2 – Define a new encryption key (test key 1)
	var key1 models.EncryptionKey
	keyMaterial1 := []byte(uuid.NewString())
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, keyMaterial1, testKekID)
		if err != nil {
			return err
		}
		key1 = ek
		return nil
	})
	assert.Nil(err)

	// --------------------------------------------------
	// 3 – Define a new data record version for test record 1 (test version 1)
	var ver1 models.RecordVersion
	version1ID := db.NewRecordVersionID()
	version1Value := []byte(uuid.NewString())
	version1Nonce := []byte(uuid.NewString())
	version1Timestamp := time.Now().UTC()
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		v, err := dbClient.DefineNewVersionForRecord(
			ctx, rec1, version1ID, key1, version1Value, version1Nonce, version1Timestamp,
		)
		if err != nil {
			return err
		}
		ver1 = v
		return nil
	})
	assert.Nil(err)
	assert.Equal(version1ID, ver1.ID)

	// --------------------------------------------------
	// 4 – Get back test version 1 and verify its content
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		v, err := dbClient.GetRecordVersion(ctx, ver1.ID)
		if err != nil {
			return err
		}
		assert.Equal(version1ID, v.ID)
		assert.Equal(rec1.ID, v.RecordID)
		assert.Equal(key1.ID, v.EncKeyID)
		assert.Equal(version1Value, v.EncValue)
		assert.Equal(version1Nonce, v.EncNonce)
		return nil
	})
	assert.Nil(err)

	// --------------------------------------------------
	// 5 – Define a new data record version for test record 1 (test version 2)
	var ver2 models.RecordVersion
	version2Value := []byte(uuid.NewString())
	version2Nonce := []byte(uuid.NewString())
	version2Timestamp := time.Now().UTC()
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		v, err := dbClient.DefineNewVersionForRecord(
			ctx, rec1, db.NewRecordVersionID(), key1, version2Value, version2Nonce, version2Timestamp,
		)
		if err != nil {
			return err
		}
		ver2 = v
		return nil
	})
	assert.Nil(err)

	// --------------------------------------------------
	// 6 – Get back test version 2 and verify its content
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		v, err := dbClient.GetRecordVersion(ctx, ver2.ID)
		if err != nil {
			return err
		}
		assert.Equal(rec1.ID, v.RecordID)
		assert.Equal(key1.ID, v.EncKeyID)
		assert.Equal(version2Value, v.EncValue)
		assert.Equal(version2Nonce, v.EncNonce)
		return nil
	})
	assert.Nil(err)
}

// TestDBCreateDataRecordVersionDelete verifies that record versions are deleted
// when their parent record or their encryption key is deleted.
//
// The test performs the following steps:
//
//   - Define two data records, `test record 1` and `test record 2`.
//   - Define one encryption key, `test key 1`.
//   - Define a new data record version for `test record 1` using `test key 1`
//     (test version 1).
//   - Verify the content of test version 1.
//   - Define a new data record version for `test record 2` using `test key 1`
//     (test version 2).
//   - Verify the content of test version 2.
//   - Delete `test record 2`.
//   - Verify that getting test version 2 fails.
//   - Delete `test key 1`.
//   - Verify that getting test version 1 fails.
func TestDBCreateDataRecordVersionDelete(t *testing.T) {
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

	// The record data API is closed outside the READY state
	markSystemReady(utCtx, t, uut)

	// ----- 1 – Define a new data record (test record 1) -----
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

	// ----- 2 – Define a new data record (test record 2) -----
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

	// ----- 3 – Define a new encryption key (test key 1) -----
	var key1 models.EncryptionKey
	keyMaterial1 := []byte(uuid.NewString())
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, keyMaterial1, testKekID)
		if err != nil {
			return err
		}
		key1 = ek
		return nil
	})
	assert.Nil(err)

	// ----- 4 – Define a new data record version for test record 1 (test version 1) -----
	var ver1 models.RecordVersion
	version1Value := []byte(uuid.NewString())
	version1Nonce := []byte(uuid.NewString())
	version1Timestamp := time.Now().UTC()
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		v, err := dbClient.DefineNewVersionForRecord(
			ctx, rec1, db.NewRecordVersionID(), key1, version1Value, version1Nonce, version1Timestamp,
		)
		if err != nil {
			return err
		}
		ver1 = v
		return nil
	})
	assert.Nil(err)

	// ----- 5 – Get back test version 1 and verify its content -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		v, err := dbClient.GetRecordVersion(ctx, ver1.ID)
		if err != nil {
			return err
		}
		assert.Equal(rec1.ID, v.RecordID)
		assert.Equal(key1.ID, v.EncKeyID)
		assert.Equal(version1Value, v.EncValue)
		assert.Equal(version1Nonce, v.EncNonce)
		return nil
	})
	assert.Nil(err)

	// ----- 6 – Define a new data record version for test record 2 (test version 2) -----
	var ver2 models.RecordVersion
	version2Value := []byte(uuid.NewString())
	version2Nonce := []byte(uuid.NewString())
	version2Timestamp := time.Now().UTC()
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		v, err := dbClient.DefineNewVersionForRecord(
			ctx, rec2, db.NewRecordVersionID(), key1, version2Value, version2Nonce, version2Timestamp,
		)
		if err != nil {
			return err
		}
		ver2 = v
		return nil
	})
	assert.Nil(err)

	// ----- 7 – Get back test version 2 and verify its content -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		v, err := dbClient.GetRecordVersion(ctx, ver2.ID)
		if err != nil {
			return err
		}
		assert.Equal(rec2.ID, v.RecordID)
		assert.Equal(key1.ID, v.EncKeyID)
		assert.Equal(version2Value, v.EncValue)
		assert.Equal(version2Nonce, v.EncNonce)
		return nil
	})
	assert.Nil(err)

	// ----- 8 – Delete test record 2 -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.DeleteRecord(ctx, rec2.ID)
	})
	assert.Nil(err)

	// ----- 9 – Get back test version 2. This should fail as not found. -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		_, err := dbClient.GetRecordVersion(ctx, ver2.ID)
		return err
	})
	var notFound goutils.NotFoundError
	assert.ErrorAs(err, &notFound, "expected not found when retrieving a version of a deleted record")

	// ----- 10 – Deleting test key 1 must fail while test version 1 still uses it -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.DeleteEncryptionKey(ctx, key1.ID)
	})
	assert.Error(err, "deleting an encryption key still in use must be refused")

	// ----- 11 – Test version 1 is untouched by the refused delete -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		v, err := dbClient.GetRecordVersion(ctx, ver1.ID)
		if err != nil {
			return err
		}
		assert.Equal(key1.ID, v.EncKeyID)
		assert.Equal(version1Value, v.EncValue)
		return nil
	})
	assert.Nil(err, "a refused encryption key delete must not disturb the data it protects")

	// ----- 12 – Once nothing references it, test key 1 can be deleted -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.DeleteRecord(ctx, rec1.ID)
	})
	assert.Nil(err)

	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		return dbClient.DeleteEncryptionKey(ctx, key1.ID)
	})
	assert.Nil(err)

	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		_, err := dbClient.GetEncryptionKey(ctx, key1.ID)
		return err
	})
	assert.ErrorAs(err, &notFound)
}

func TestDBListDataRecordVersion(t *testing.T) {
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

	// The record data API is closed outside the READY state
	markSystemReady(utCtx, t, uut)

	// ----- 1 – Define two data records (test record 1 & 2) -----
	var rec1, rec2 models.Record
	rec1Name := uuid.NewString()
	rec2Name := uuid.NewString()

	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec1Name)
		if err != nil {
			return err
		}
		rec1 = r
		return nil
	})
	assert.Nil(err)

	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		r, err := dbClient.DefineNewRecord(ctx, rec2Name)
		if err != nil {
			return err
		}
		rec2 = r
		return nil
	})
	assert.Nil(err)

	// ----- 2 – Define two encryption keys (test key 1 & 2) -----
	var key1, key2 models.EncryptionKey
	key1Mat := []byte(uuid.NewString())
	key2Mat := []byte(uuid.NewString())

	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, key1Mat, testKekID)
		if err != nil {
			return err
		}
		key1 = ek
		return nil
	})
	assert.Nil(err)

	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		ek, err := dbClient.RecordEncryptionKey(ctx, key2Mat, testKekID)
		if err != nil {
			return err
		}
		key2 = ek
		return nil
	})
	assert.Nil(err)

	// ----- 3 – Define four record versions -----
	var ver1, ver2, ver3, ver4 models.RecordVersion
	now := time.Now().UTC()

	createVersion := func(
		rec models.Record, key models.EncryptionKey, value, nonce []byte,
	) (models.RecordVersion, error) {
		var newVersion models.RecordVersion
		return newVersion, uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				var err error
				newVersion, err = dbClient.DefineNewVersionForRecord(
					ctx, rec, db.NewRecordVersionID(), key, value, nonce, now,
				)
				return err
			},
		)
	}

	ver1, err = createVersion(rec1, key1, []byte(uuid.NewString()), []byte(uuid.NewString()))
	assert.Nil(err)

	ver2, err = createVersion(rec2, key1, []byte(uuid.NewString()), []byte(uuid.NewString()))
	assert.Nil(err)

	ver3, err = createVersion(rec1, key2, []byte(uuid.NewString()), []byte(uuid.NewString()))
	assert.Nil(err)

	ver4, err = createVersion(rec2, key2, []byte(uuid.NewString()), []byte(uuid.NewString()))
	assert.Nil(err)

	// Helper to verify a version against its expected data
	verifyVersion := func(
		v models.RecordVersion,
		expRecord models.Record,
		expKey models.EncryptionKey,
		expValue, expNonce []byte,
	) {
		assert.Equal(expRecord.ID, v.RecordID)
		assert.Equal(expKey.ID, v.EncKeyID)
		assert.Equal(expValue, v.EncValue)
		assert.Equal(expNonce, v.EncNonce)
	}

	// ----- 4 – List versions of test record 1 -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		filters := db.RecordVersionQueryFilter{}
		vers, err := dbClient.ListVersionsOfOneRecord(ctx, rec1, filters)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		// Find by ID and verify
		for _, v := range vers {
			switch v.ID {
			case ver1.ID:
				verifyVersion(v, rec1, key1, ver1.EncValue, ver1.EncNonce)
				seen[v.ID] = true
			case ver3.ID:
				verifyVersion(v, rec1, key2, ver3.EncValue, ver3.EncNonce)
				seen[v.ID] = true
			default:
				assert.Fail("unexpected version ID %s", v.ID)
			}
		}
		assert.Len(seen, 2)
		return nil
	})
	assert.Nil(err)

	// ----- 5 – List versions of test record 2 -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		filters := db.RecordVersionQueryFilter{}
		vers, err := dbClient.ListVersionsOfOneRecord(ctx, rec2, filters)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, v := range vers {
			switch v.ID {
			case ver2.ID:
				verifyVersion(v, rec2, key1, ver2.EncValue, ver2.EncNonce)
				seen[v.ID] = true
			case ver4.ID:
				verifyVersion(v, rec2, key2, ver4.EncValue, ver4.EncNonce)
				seen[v.ID] = true
			default:
				assert.Fail("unexpected version ID %s", v.ID)
			}
		}
		assert.Len(seen, 2)
		return nil
	})
	assert.Nil(err)

	// ----- 6 – List versions encrypted by test key 1 -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		filters := db.RecordVersionQueryFilter{}
		vers, err := dbClient.ListVersionsEncryptedByKey(ctx, key1, filters)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, v := range vers {
			switch v.ID {
			case ver1.ID:
				verifyVersion(v, rec1, key1, ver1.EncValue, ver1.EncNonce)
				seen[v.ID] = true
			case ver2.ID:
				verifyVersion(v, rec2, key1, ver2.EncValue, ver2.EncNonce)
				seen[v.ID] = true
			default:
				assert.Fail("unexpected version ID %s", v.ID)
			}
		}
		assert.Len(seen, 2)
		return nil
	})
	assert.Nil(err)

	// ----- 7 – List versions encrypted by test key 2 -----
	err = uut.UseDatabaseInTransaction(utCtx, func(ctx context.Context, dbClient db.Database) error {
		filters := db.RecordVersionQueryFilter{}
		vers, err := dbClient.ListVersionsEncryptedByKey(ctx, key2, filters)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, v := range vers {
			switch v.ID {
			case ver3.ID:
				verifyVersion(v, rec1, key2, ver3.EncValue, ver3.EncNonce)
				seen[v.ID] = true
			case ver4.ID:
				verifyVersion(v, rec2, key2, ver4.EncValue, ver4.EncNonce)
				seen[v.ID] = true
			default:
				assert.Fail("unexpected version ID %s", v.ID)
			}
		}
		assert.Len(seen, 2)
		return nil
	})
	assert.Nil(err)
}

// TestDBCountRecordVersions verifies the behaviour of CountRecordVersions, which sizes the
// work an encryption key rotation still has ahead of it.
func TestDBCountRecordVersions(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut := newTestDBClient(utCtx, t)
	markSystemReady(utCtx, t, uut)

	// Two keys, and records split across them
	var key1, key2 models.EncryptionKey
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			if key1, err = dbClient.RecordEncryptionKey(
				ctx, []byte(uuid.NewString()), testKekID,
			); err != nil {
				return err
			}
			key2, err = dbClient.RecordEncryptionKey(ctx, []byte(uuid.NewString()), testKekID)
			return err
		},
	))

	var recordA, recordB models.Record
	assert.Nil(uut.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			var err error
			if recordA, err = dbClient.DefineNewRecord(ctx, uuid.NewString()); err != nil {
				return err
			}
			recordB, err = dbClient.DefineNewRecord(ctx, uuid.NewString())
			return err
		},
	))

	// Three versions on recordA under key1, one on recordB under key2
	newVersion := func(record models.Record, encKey models.EncryptionKey) {
		assert.Nil(uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				_, err := dbClient.DefineNewVersionForRecord(
					ctx,
					record,
					db.NewRecordVersionID(),
					encKey,
					[]byte(uuid.NewString()),
					[]byte(uuid.NewString()),
					time.Now().UTC(),
				)
				return err
			},
		))
	}
	newVersion(recordA, key1)
	newVersion(recordA, key1)
	newVersion(recordA, key1)
	newVersion(recordB, key2)

	count := func(filters db.RecordVersionQueryFilter) int64 {
		var total int64
		assert.Nil(uut.UseDatabaseInTransaction(
			utCtx, func(ctx context.Context, dbClient db.Database) error {
				var err error
				total, err = dbClient.CountRecordVersions(ctx, filters)
				return err
			},
		))
		return total
	}

	assert.EqualValues(4, count(db.RecordVersionQueryFilter{}))
	assert.EqualValues(3, count(db.RecordVersionQueryFilter{TargetRecordID: &recordA.ID}))
	assert.EqualValues(1, count(db.RecordVersionQueryFilter{TargetRecordID: &recordB.ID}))
	assert.EqualValues(3, count(db.RecordVersionQueryFilter{TargetEncKeyID: &key1.ID}))
	assert.EqualValues(1, count(db.RecordVersionQueryFilter{TargetEncKeyID: &key2.ID}))

	// Both conditions together
	assert.EqualValues(0, count(db.RecordVersionQueryFilter{
		TargetRecordID: &recordB.ID, TargetEncKeyID: &key1.ID,
	}))

	// Paging is ignored: the count of one page is not a useful number
	limit, offset := 2, 1
	assert.EqualValues(4, count(db.RecordVersionQueryFilter{
		CommonListEntryQueryFilter: db.CommonListEntryQueryFilter{Limit: &limit, Offset: &offset},
	}))

	// An unknown key matches nothing
	unknown := uuid.NewString()
	assert.EqualValues(0, count(db.RecordVersionQueryFilter{TargetEncKeyID: &unknown}))
}
