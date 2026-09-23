package haven_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/alwitt/haven"
	"github.com/alwitt/haven/db"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestProtectedKVStoreEndToEnd performs a full end‑to‑end test of the
// ProtectedKVStore.  The flow closely mirrors the integration tests for the
// encryption key APIs – a temporary SQLite database is created, the
// `haven.NewProtectedKVStore` constructor is exercised, and key/value
// records are written, read, updated, and finally deleted.
func TestProtectedKVStoreEndToEnd(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	// ------------------------------------------------------------------
	// 1. Create a temporary SQLite database
	// ------------------------------------------------------------------
	ctx := context.Background()

	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	dbClient, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)

	// Create tables
	assert.Nil(dbClient.RunSQLInTransaction(ctx, db.DefineTables))

	// ------------------------------------------------------------------
	// 2. Load RSA key files, using a certificate that must verify against a CA chain
	// ------------------------------------------------------------------
	certFile, err := filepath.Abs("./test/certs/user-intermediate.crt")
	assert.Nil(err)
	keyFile, err := filepath.Abs("./test/certs/user-intermediate.key")
	assert.Nil(err)
	caCertFile, err := filepath.Abs("./test/certs/ca-chain.crt")
	assert.Nil(err)

	storeParams := haven.ProtectedKVStoreParams{
		DBDialector:          db.GetSqliteDialector(testDB),
		DBLogLevel:           logger.Error,
		PrimaryRSACertFile:   certFile,
		PrimaryRSAKeyFile:    keyFile,
		PrimaryRSACACertFile: &caCertFile,
		KeyCacheTTL:          time.Minute,
	}

	// ------------------------------------------------------------------
	// 3. Initialize the system, then create the protected KV store
	// ------------------------------------------------------------------
	// The record data API is closed until a maintenance action mints the first encryption
	// key and opens the system for normal operation.
	runner, _, err := haven.NewMaintenanceRunner(ctx, storeParams, 0)
	assert.Nil(err)
	assert.Nil(runner.Initialize(ctx))

	store, _, err := haven.NewProtectedKVStore(ctx, storeParams)
	assert.Nil(err)

	// ------------------------------------------------------------------
	// 4. Record the first key/value pair
	// ------------------------------------------------------------------
	keyName := "testkey1"
	value1 := []byte(uuid.NewString())
	timestamp1 := time.Now()

	rec, ver1, err := store.RecordKeyValue(ctx, keyName, value1, timestamp1, nil)
	assert.Nil(err)
	assert.NotEmpty(rec.ID)
	assert.NotEmpty(ver1.ID)

	// ------------------------------------------------------------------
	// 5. List versions – should return exactly one entry
	// ------------------------------------------------------------------
	_, versions, err := store.ListKeyVersions(ctx, keyName, nil)
	assert.Nil(err)
	assert.Len(versions, 1)
	assert.Equal(ver1.ID, versions[0].ID)

	// ------------------------------------------------------------------
	// 6. Fetch value by version ID and verify it matches the original
	// ------------------------------------------------------------------
	retrieved, err := store.GetValueOfKeyAtVersionID(ctx, ver1.ID, nil)
	assert.Nil(err)
	assert.Equal(value1, retrieved)

	// ------------------------------------------------------------------
	// 7. Record a second version for the same key
	// ------------------------------------------------------------------
	value2 := []byte(uuid.NewString())
	_, ver2, err := store.RecordKeyValue(ctx, keyName, value2, time.Now(), nil)
	assert.Nil(err)

	// The record ID should be unchanged
	assert.Equal(rec.ID, ver2.RecordID)

	// ------------------------------------------------------------------
	// 8. List versions again – should return two entries
	// ------------------------------------------------------------------
	_, versions, err = store.ListKeyVersions(ctx, keyName, nil)
	assert.Nil(err)
	assert.Len(versions, 2)

	// Verify that both version IDs are present
	ids := map[string]bool{versions[0].ID: true, versions[1].ID: true}
	assert.True(ids[ver1.ID])
	assert.True(ids[ver2.ID])

	// ------------------------------------------------------------------
	// 9. Fetch the second value using the RecordVersion object
	// ------------------------------------------------------------------
	retrieved2, err := store.GetValueOfKeyAtVersion(ctx, ver2, nil)
	assert.Nil(err)
	assert.Equal(value2, retrieved2)

	// ------------------------------------------------------------------
	// 10. Delete the key
	// ------------------------------------------------------------------
	assert.Nil(store.DeleteKey(ctx, keyName, nil))

	// ------------------------------------------------------------------
	// 11. Attempt to list versions again – should fail
	// ------------------------------------------------------------------
	_, _, err = store.ListKeyVersions(ctx, keyName, nil)
	assert.Error(err)
}

// TestProtectedKVStoreRowBinding verifies a version's cipher text is bound to its row.
// It simulates an attacker with write access to the table by swapping the encrypted
// value and nonce between rows with raw SQL, and expects decryption to fail afterwards.
func TestProtectedKVStoreRowBinding(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	ctx := context.Background()

	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	dbClient, err := db.NewConnection(db.GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)
	assert.Nil(dbClient.RunSQLInTransaction(ctx, db.DefineTables))

	certFile, err := filepath.Abs("./test/certs/self-signed.crt")
	assert.Nil(err)
	keyFile, err := filepath.Abs("./test/certs/self-signed.key")
	assert.Nil(err)

	storeParams := haven.ProtectedKVStoreParams{
		DBDialector:        db.GetSqliteDialector(testDB),
		DBLogLevel:         logger.Error,
		PrimaryRSACertFile: certFile,
		PrimaryRSAKeyFile:  keyFile,
		KeyCacheTTL:        time.Minute,
	}

	// The record data API is closed until a maintenance action opens the system
	runner, _, err := haven.NewMaintenanceRunner(ctx, storeParams, 0)
	assert.Nil(err)
	assert.Nil(runner.Initialize(ctx))

	store, _, err := haven.NewProtectedKVStore(ctx, storeParams)
	assert.Nil(err)

	// ------------------------------------------------------------------
	// 1. Two versions of key A, one version of key B
	// ------------------------------------------------------------------
	valueA1 := []byte(uuid.NewString())
	_, verA1, err := store.RecordKeyValue(ctx, "keyA", valueA1, time.Now(), nil)
	assert.Nil(err)
	valueA2 := []byte(uuid.NewString())
	_, verA2, err := store.RecordKeyValue(ctx, "keyA", valueA2, time.Now(), nil)
	assert.Nil(err)
	valueB1 := []byte(uuid.NewString())
	_, verB1, err := store.RecordKeyValue(ctx, "keyB", valueB1, time.Now(), nil)
	assert.Nil(err)

	for _, entry := range []struct {
		versionID string
		value     []byte
	}{
		{versionID: verA1.ID, value: valueA1},
		{versionID: verA2.ID, value: valueA2},
		{versionID: verB1.ID, value: valueB1},
	} {
		retrieved, err := store.GetValueOfKeyAtVersionID(ctx, entry.versionID, nil)
		assert.Nil(err)
		assert.Equal(entry.value, retrieved)
	}

	// swapVersionPayload exchanges the encrypted value and nonce between two version rows
	swapVersionPayload := func(versionID1, versionID2 string) error {
		return dbClient.RunSQLInTransaction(ctx, func(_ context.Context, tx *gorm.DB) error {
			var rows []struct {
				ID       string
				EncValue []byte
				EncNonce []byte
			}
			if err := tx.Table("record_versions").
				Select("id", "enc_value", "enc_nonce").
				Where("id IN ?", []string{versionID1, versionID2}).
				Find(&rows).Error; err != nil {
				return err
			}
			if len(rows) != 2 {
				return fmt.Errorf("expected 2 rows, found %d", len(rows))
			}
			for i := range 2 {
				other := rows[1-i]
				if err := tx.Table("record_versions").
					Where("id = ?", rows[i].ID).
					Updates(map[string]any{
						"enc_value": other.EncValue, "enc_nonce": other.EncNonce,
					}).Error; err != nil {
					return err
				}
			}
			return nil
		})
	}

	// ------------------------------------------------------------------
	// 2. Swap payloads between two versions of the same key
	// ------------------------------------------------------------------
	assert.Nil(swapVersionPayload(verA1.ID, verA2.ID))
	_, err = store.GetValueOfKeyAtVersionID(ctx, verA1.ID, nil)
	assert.Error(err)
	_, err = store.GetValueOfKeyAtVersionID(ctx, verA2.ID, nil)
	assert.Error(err)
	// Untouched row still reads
	retrieved, err := store.GetValueOfKeyAtVersionID(ctx, verB1.ID, nil)
	assert.Nil(err)
	assert.Equal(valueB1, retrieved)

	// ------------------------------------------------------------------
	// 3. Swap payloads between versions of different keys
	// ------------------------------------------------------------------
	assert.Nil(swapVersionPayload(verA1.ID, verB1.ID))
	_, err = store.GetValueOfKeyAtVersionID(ctx, verA1.ID, nil)
	assert.Error(err)
	_, err = store.GetValueOfKeyAtVersionID(ctx, verB1.ID, nil)
	assert.Error(err)
}
