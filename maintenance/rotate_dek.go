package maintenance

import (
	"context"
	"fmt"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
)

/*
RotateEncryptionKey replace the encryption key, and move every record version onto it

	@param ctx context.Context - execution context
*/
func (r *runner) RotateEncryptionKey(ctx context.Context) error {
	if err := r.rotateEncryptionKey(ctx); err != nil {
		return models.NewMaintenanceError("failed to rotate the encryption key", err, true)
	}
	return nil
}

// rotateEncryptionKey the steps of an encryption key rotation, in order
//
// Each step names the transaction it commits in, because the boundaries are what make the
// rotation resumable rather than an implementation detail of it.
func (r *runner) rotateEncryptionKey(ctx context.Context) error {
	// Step (a): open the rotation. This commits on its own, and before any work starts, so
	// the persistence layer refuses record writes for the rotation's whole duration.
	if err := r.openDEKRotation(ctx); err != nil {
		return err
	}

	// Step (b): retire the key holding the data, and mint the one it is moving to. A
	// rotation resumed after this committed finds the retired key and skips straight to the
	// drain.
	newKey, err := r.supersedeEncryptionKey(ctx)
	if err != nil {
		return err
	}

	// Step (c): move every version off the retired keys
	if err := r.drainRetiredKeys(ctx, newKey); err != nil {
		return err
	}

	// Step (d): close the rotation
	return r.closeDEKRotation(ctx)
}

// openDEKRotation transition the system into an encryption key rotation
//
// A system already in the rotation state is being resumed, which is not an error.
func (r *runner) openDEKRotation(ctx context.Context) error {
	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			params, err := requireState(
				dbCtx,
				dbClient,
				"rotate the encryption key",
				models.SystemStateReady,
				models.SystemStateDEKRotating,
			)
			if err != nil {
				return err
			}

			if params.State == models.SystemStateDEKRotating {
				// Resuming an interrupted rotation
				return nil
			}

			return dbClient.MarkSystemRotatingDEK(dbCtx)
		},
	); dbErr != nil {
		return goutils.NewRuntimeError("failed to open the encryption key rotation", dbErr, true)
	}

	return nil
}

/*
supersedeEncryptionKey retire the active encryption key and mint its replacement

Both happen in one transaction, so no other connection ever observes two active keys or
none.

A retired key already existing means this committed before the rotation was interrupted; the
replacement is the active key which is already there, and minting another would leave the
drain moving data onto a key a third rotation would have to move it off again.

	@param ctx context.Context - execution context
	@returns the encryption key the data is moving onto
*/
func (r *runner) supersedeEncryptionKey(ctx context.Context) (models.EncryptionKey, error) {
	var newKey models.EncryptionKey

	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			retired, err := listKeysInState(dbCtx, dbClient, models.EncryptionKeyStateRetired)
			if err != nil {
				return err
			}

			active, err := listKeysInState(dbCtx, dbClient, models.EncryptionKeyStateActive)
			if err != nil {
				return err
			}

			if len(retired) > 0 {
				// This step already committed: the active key is the replacement
				if len(active) != 1 {
					return goutils.NewConsistencyError(
						fmt.Sprintf(
							"an interrupted rotation left %d active encryption keys; expected exactly 1",
							len(active),
						),
						nil, true,
					)
				}
				newKey = active[0]
				return nil
			}

			if len(active) != 1 {
				return goutils.NewConsistencyError(
					fmt.Sprintf(
						"the system holds %d active encryption keys; expected exactly 1", len(active),
					),
					nil, true,
				)
			}

			if err := dbClient.MarkEncryptionKeyRetired(dbCtx, active[0].ID); err != nil {
				return goutils.NewPersistenceError(
					fmt.Sprintf("failed to retire encryption key %s", active[0].ID), err, true,
				)
			}

			newKey, err = r.cryptoEngine.NewEncryptionKey(dbCtx, dbClient)
			if err != nil {
				return goutils.NewPersistenceError("failed to define the new encryption key", err, true)
			}

			return nil
		},
	); dbErr != nil {
		return models.EncryptionKey{}, goutils.NewRuntimeError(
			"failed to supersede the active encryption key", dbErr, true,
		)
	}

	return newKey, nil
}

// drainRetiredKeys move every record version under a retired key onto the given key
//
// Halts on the first version which will not decrypt, leaving the system in the rotation
// state. See ListUndecryptableVersions.
func (r *runner) drainRetiredKeys(ctx context.Context, newKey models.EncryptionKey) error {
	retired, err := r.retiredKeys(ctx)
	if err != nil {
		return err
	}

	for _, key := range retired {
		if err := r.drainOneKey(ctx, key, newKey); err != nil {
			return goutils.NewRuntimeError(
				fmt.Sprintf("failed to move record versions off encryption key %s", key.ID), err, true,
			)
		}
	}

	return nil
}

// drainOneKey move every record version under one encryption key onto another
//
// The query selects on the very column the conversion then changes, so each page is
// requested from offset zero and the loop ends when one comes back empty. Advancing an
// offset would skip the rows which shifted into positions already passed.
func (r *runner) drainOneKey(
	ctx context.Context, sourceKey, targetKey models.EncryptionKey,
) error {
	for {
		var batch []models.RecordVersion

		if err := r.persistence.UseDatabaseInTransaction(
			ctx, func(dbCtx context.Context, dbClient db.Database) error {
				var err error
				batch, err = dbClient.ListVersionsEncryptedByKey(
					dbCtx,
					sourceKey,
					db.RecordVersionQueryFilter{
						CommonListEntryQueryFilter: db.CommonListEntryQueryFilter{Limit: &r.pageSize},
					},
				)
				if err != nil {
					return goutils.NewPersistenceError(
						"failed to list the record versions to move", err, true,
					)
				}

				if len(batch) == 0 {
					return nil
				}

				return r.cryptoEngine.ReEncryptRecordVersions(dbCtx, batch, targetKey, dbClient)
			},
		); err != nil {
			return err
		}

		if len(batch) == 0 {
			return nil
		}
	}
}

// closeDEKRotation delete the retired keys and return the system to normal operation
//
// Both happen in one transaction. Were they separate, a rotation which finished its work but
// crashed before the transition would be indistinguishable from one which never started, and
// resuming it would mint a third key and move every version again.
//
// The delete is also the completion proof: a record version still referencing a retired key
// violates the foreign key, so the transaction aborts and the system stays in the rotation
// state rather than reporting success over incomplete work.
func (r *runner) closeDEKRotation(ctx context.Context) error {
	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			retired, err := listKeysInState(dbCtx, dbClient, models.EncryptionKeyStateRetired)
			if err != nil {
				return err
			}

			for _, key := range retired {
				if err := dbClient.DeleteEncryptionKey(dbCtx, key.ID); err != nil {
					return goutils.NewPersistenceError(
						fmt.Sprintf(
							"failed to delete retired encryption key %s; record versions may still "+
								"reference it",
							key.ID,
						),
						err, true,
					)
				}
			}

			return dbClient.MarkSystemReady(dbCtx)
		},
	); dbErr != nil {
		return goutils.NewRuntimeError("failed to close the encryption key rotation", dbErr, true)
	}

	return nil
}

// retiredKeys list the encryption keys which only decrypt
func (r *runner) retiredKeys(ctx context.Context) ([]models.EncryptionKey, error) {
	var keys []models.EncryptionKey

	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			var err error
			keys, err = listKeysInState(dbCtx, dbClient, models.EncryptionKeyStateRetired)
			return err
		},
	); dbErr != nil {
		return nil, dbErr
	}

	return keys, nil
}
