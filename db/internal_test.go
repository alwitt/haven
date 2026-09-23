package db

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// newInternalTestClient prepare a persistence client, the GORM handle behind it, and a
// database client over that handle
//
// The handle is what lets a test reach in between a read and the write which follows it.
func newInternalTestClient(
	utCtx context.Context, t *testing.T,
) (*clientImpl, *databaseImpl) {
	assert := assert.New(t)

	testDB := fmt.Sprintf("/tmp/haven_ut_%s.db", ulid.Make().String())
	log.WithField("db", testDB).Debug("Test database")

	client, err := NewConnection(GetSqliteDialector(testDB), logger.Error)
	assert.Nil(err)
	assert.Nil(client.RunSQLInTransaction(utCtx, DefineTables))

	impl, ok := client.(*clientImpl)
	assert.True(ok)

	dbClient, err := newDatabase(utCtx, impl.db)
	assert.Nil(err)
	dbImpl, ok := dbClient.(*databaseImpl)
	assert.True(ok)

	return impl, dbImpl
}

// stampCreatedAt give an entry a known creation timestamp
//
// Every listing orders on created_at, and rows inserted in a loop can land on the same
// instant. Setting the sort key explicitly is what keeps a paging assertion about paging
// rather than about how fast the inserts ran.
func stampCreatedAt(
	t *testing.T, impl *clientImpl, model interface{}, id string, at time.Time,
) {
	assert.New(t).Nil(
		impl.db.Model(model).Where("id = ?", id).Update("created_at", at).Error,
	)
}

// maxPagedEntries the most entries pageThrough will walk before it gives up
//
// Comfortably above what any test here creates, and low enough that giving up is quick.
const maxPagedEntries = 100

// pageThrough walk a listing one page at a time, returning what it yielded in order
//
// The walk is bounded rather than open ended: a listing which ignored its offset would hand
// back the same page forever, and a test which hangs reports nothing to whoever broke it.
func pageThrough(
	t *testing.T, pageSize int, list func(filter CommonListEntryQueryFilter) []string,
) []string {
	seen := []string{}

	for offset := 0; offset <= maxPagedEntries; offset += pageSize {
		pageOffset := offset
		batch := list(CommonListEntryQueryFilter{Limit: &pageSize, Offset: &pageOffset})
		if len(batch) == 0 {
			return seen
		}
		seen = append(seen, batch...)
	}

	assert.New(t).Fail("the listing never ran out of pages; its offset is not advancing")
	return seen
}

// TestSystemStateTransitionDetectsConcurrentChange verifies that a transition whose row moved
// between the read and the write aborts rather than overwriting it.
//
// DESIGN §5.1: a transition is a read, a validation, then a write conditional on the state
// that was read. That condition is what makes two operators running maintenance actions
// concurrently safe without a lock — one wins, and the other is told which state the system
// is actually in. Nothing reaches it through the public API, because the read and the write
// are a single call; here the write is intercepted so the row can change underneath it the
// way another connection would change it.
func TestSystemStateTransitionDetectsConcurrentChange(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	impl, dbClient := newInternalTestClient(utCtx, t)

	// Start from READY, which either rotation may legally open from
	assert.Nil(dbClient.MarkSystemReady(utCtx))

	// Registered only now, so it cannot disturb the transition above
	const callbackName = "haven_ut_concurrent_state_change"
	var interfered bool
	assert.Nil(impl.db.Callback().Update().Before("gorm:update").Register(
		callbackName,
		func(tx *gorm.DB) {
			if interfered || tx.Statement.Table != "system_params" {
				return
			}
			interfered = true

			// Issued on the connection the pending statement is about to use, so nothing
			// blocks, and as raw SQL so it does not re-enter the update callbacks
			_, execErr := tx.Statement.ConnPool.ExecContext(
				utCtx,
				"UPDATE system_params SET state = ? WHERE id = ?",
				string(models.SystemStateKEKRotating),
				GlobalSystemParamEntryID,
			)
			assert.Nil(execErr)
		},
	))
	defer func() { assert.Nil(impl.db.Callback().Update().Remove(callbackName)) }()

	// A KEK rotation took the system while this one was deciding to start a DEK rotation
	transitioned := dbClient.MarkSystemRotatingDEK(utCtx)
	assert.True(interfered, "the state must change between the read and the write")
	assert.Error(transitioned)

	// The refusal names the state which was read and the one it wanted, which is what an
	// operator needs to work out who won
	var consistencyErr goutils.ConsistencyError
	assert.True(errors.As(transitioned, &consistencyErr))
	assert.ErrorContains(transitioned, string(models.SystemStateReady))
	assert.ErrorContains(transitioned, string(models.SystemStateDEKRotating))

	// The winner's transition stands, and the loser wrote nothing over it
	params, err := dbClient.GetSystemParamEntry(utCtx)
	assert.Nil(err)
	assert.Equal(models.SystemStateKEKRotating, params.State)

	// Nor did it log an audit event for a transition which never happened
	events, err := dbClient.ListSystemEvents(utCtx, SystemEventQueryFilter{
		EventTypes: []models.SystemEventTypeENUMType{models.SystemEventTypeDEKRotationStarted},
	})
	assert.Nil(err)
	assert.Empty(events)
}

// internalTestKekID stands in for the ID of a primary RSA key pair
const internalTestKekID = "0f9a1c7b3e5d2846a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071"

// TestSystemEventListPagingAndWindow verifies how the audit log listing pages, and what its
// timestamp bounds actually include.
//
// The bounds are the reason this matters beyond paging: "after" and "before" read as
// exclusive, and the query is inclusive at both ends. An operator pulling a window of the
// audit log around an incident gets the events on the boundary, which is the behaviour to
// pin down rather than leave to whoever next reads the SQL.
func TestSystemEventListPagingAndWindow(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	impl, dbClient := newInternalTestClient(utCtx, t)

	// Five events a minute apart, which is the order the listing returns them in
	base := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	oldestFirst := []string{}
	for idx := 0; idx < 5; idx++ {
		entry, err := dbClient.defineNewSystemEvent(models.SystemEventTypeInitialized, nil)
		assert.Nil(err)
		stampCreatedAt(
			t, impl, &SystemEventAuditDBEntry{}, entry.ID,
			base.Add(time.Duration(idx)*time.Minute),
		)
		oldestFirst = append(oldestFirst, entry.ID)
	}

	listIDs := func(filter SystemEventQueryFilter) []string {
		entries, err := dbClient.ListSystemEvents(utCtx, filter)
		assert.Nil(err)
		ids := []string{}
		for _, entry := range entries {
			ids = append(ids, entry.ID)
		}
		return ids
	}

	// Unpaged, the audit log reads oldest first
	assert.Equal(oldestFirst, listIDs(SystemEventQueryFilter{}))

	// Limit caps a page, and Offset steps past the page before it
	limit, offset := 2, 2
	assert.Equal(oldestFirst[:2], listIDs(SystemEventQueryFilter{
		CommonListEntryQueryFilter: CommonListEntryQueryFilter{Limit: &limit},
	}))
	assert.Equal(oldestFirst[2:4], listIDs(SystemEventQueryFilter{
		CommonListEntryQueryFilter: CommonListEntryQueryFilter{Limit: &limit, Offset: &offset},
	}))

	// Paging to the end yields every event exactly once, in the unpaged order
	assert.Equal(oldestFirst, pageThrough(t, 2, func(page CommonListEntryQueryFilter) []string {
		return listIDs(SystemEventQueryFilter{CommonListEntryQueryFilter: page})
	}))

	// Both bounds are inclusive: the events sitting exactly on them are returned
	after, before := base.Add(time.Minute), base.Add(3*time.Minute)
	assert.Equal(oldestFirst[1:4], listIDs(SystemEventQueryFilter{
		EventsAfter: &after, EventsBefore: &before,
	}))

	// And each bound stands on its own
	assert.Equal(oldestFirst[1:], listIDs(SystemEventQueryFilter{EventsAfter: &after}))
	assert.Equal(oldestFirst[:4], listIDs(SystemEventQueryFilter{EventsBefore: &before}))

	// A window holding no events comes back empty rather than unfiltered
	distant := base.Add(time.Hour)
	assert.Empty(listIDs(SystemEventQueryFilter{EventsAfter: &distant}))

	// The window and the page compose: the bounds select, then the page cuts
	assert.Equal(oldestFirst[1:3], listIDs(SystemEventQueryFilter{
		CommonListEntryQueryFilter: CommonListEntryQueryFilter{Limit: &limit},
		EventsAfter:                &after,
		EventsBefore:               &before,
	}))
}

// TestEncryptionKeyListPaging verifies that the encryption key listing pages, newest first.
func TestEncryptionKeyListPaging(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	impl, dbClient := newInternalTestClient(utCtx, t)

	base := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	newestFirst := []string{}
	for idx := 0; idx < 5; idx++ {
		entry, err := dbClient.RecordEncryptionKey(
			utCtx, fmt.Appendf(nil, "wrapped-key-material-%d", idx), internalTestKekID,
		)
		assert.Nil(err)
		stampCreatedAt(
			t, impl, &EncryptionKeyDBEntry{}, entry.ID,
			base.Add(time.Duration(idx)*time.Minute),
		)
		// The listing runs newest first, so each key goes ahead of the ones before it
		newestFirst = append([]string{entry.ID}, newestFirst...)
	}

	listIDs := func(filter EncryptionKeyQueryFilter) []string {
		entries, err := dbClient.ListEncryptionKeys(utCtx, filter)
		assert.Nil(err)
		ids := []string{}
		for _, entry := range entries {
			ids = append(ids, entry.ID)
		}
		return ids
	}

	assert.Equal(newestFirst, listIDs(EncryptionKeyQueryFilter{}))

	limit, offset := 2, 2
	assert.Equal(newestFirst[:2], listIDs(EncryptionKeyQueryFilter{
		CommonListEntryQueryFilter: CommonListEntryQueryFilter{Limit: &limit},
	}))
	assert.Equal(newestFirst[2:4], listIDs(EncryptionKeyQueryFilter{
		CommonListEntryQueryFilter: CommonListEntryQueryFilter{Limit: &limit, Offset: &offset},
	}))

	assert.Equal(newestFirst, pageThrough(t, 2, func(page CommonListEntryQueryFilter) []string {
		return listIDs(EncryptionKeyQueryFilter{CommonListEntryQueryFilter: page})
	}))

	// The state filter and the page compose, which is what a drain over retired keys needs
	assert.Nil(dbClient.MarkEncryptionKeyRetired(utCtx, newestFirst[0]))
	assert.Equal(
		[]string{newestFirst[0]},
		listIDs(EncryptionKeyQueryFilter{
			TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateRetired},
		}),
	)
}

// TestRecordListPaging verifies that the data record listing pages, newest first.
func TestRecordListPaging(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	impl, dbClient := newInternalTestClient(utCtx, t)

	// Records may only be defined while the system is open for business
	assert.Nil(dbClient.MarkSystemReady(utCtx))

	base := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	newestFirst := []string{}
	for idx := 0; idx < 5; idx++ {
		entry, err := dbClient.DefineNewRecord(utCtx, fmt.Sprintf("key-%d", idx))
		assert.Nil(err)
		stampCreatedAt(
			t, impl, &RecordDBEntry{}, entry.ID, base.Add(time.Duration(idx)*time.Minute),
		)
		newestFirst = append([]string{entry.ID}, newestFirst...)
	}

	listIDs := func(filter RecordQueryFilter) []string {
		entries, err := dbClient.ListRecords(utCtx, filter)
		assert.Nil(err)
		ids := []string{}
		for _, entry := range entries {
			ids = append(ids, entry.ID)
		}
		return ids
	}

	assert.Equal(newestFirst, listIDs(RecordQueryFilter{}))

	limit, offset := 2, 2
	assert.Equal(newestFirst[:2], listIDs(RecordQueryFilter{
		CommonListEntryQueryFilter: CommonListEntryQueryFilter{Limit: &limit},
	}))
	assert.Equal(newestFirst[2:4], listIDs(RecordQueryFilter{
		CommonListEntryQueryFilter: CommonListEntryQueryFilter{Limit: &limit, Offset: &offset},
	}))

	assert.Equal(newestFirst, pageThrough(t, 2, func(page CommonListEntryQueryFilter) []string {
		return listIDs(RecordQueryFilter{CommonListEntryQueryFilter: page})
	}))
}
