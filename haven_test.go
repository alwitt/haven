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
	// 2. Load RSA key files
	// ------------------------------------------------------------------
	certFile, err := filepath.Abs("./test/ut_rsa.crt")
	assert.Nil(err)
	keyFile, err := filepath.Abs("./test/ut_rsa.key")
	assert.Nil(err)

	// ------------------------------------------------------------------
	// 3. Create the protected KV store
	// ------------------------------------------------------------------
	store, err := haven.NewProtectedKVStore(
		ctx, db.GetSqliteDialector(testDB), logger.Error, certFile, keyFile,
	)
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
