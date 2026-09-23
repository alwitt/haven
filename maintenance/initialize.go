package maintenance

import (
	"context"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
)

/*
Initialize prepare a system for normal operation

	@param ctx context.Context - execution context
*/
func (r *runner) Initialize(ctx context.Context) error {
	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			// Initializing a system which already holds a key would mint a second one. The
			// transition to READY is a legal no-op from READY, so nothing further down
			// catches it.
			if _, err := requireState(
				dbCtx, dbClient, "initialize the system", models.SystemStatePreInit,
			); err != nil {
				return err
			}

			if _, err := r.cryptoEngine.NewEncryptionKey(dbCtx, dbClient); err != nil {
				return goutils.NewPersistenceError("failed to define the first encryption key", err, true)
			}

			// The audit event is written by the transition itself
			return dbClient.MarkSystemReady(dbCtx)
		},
	); dbErr != nil {
		return models.NewMaintenanceError("failed to initialize the system", dbErr, true)
	}

	return nil
}
