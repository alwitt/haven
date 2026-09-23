package maintenance

import (
	"context"
	"fmt"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	"github.com/alwitt/haven/models"
)

/*
RotateKEK re-wrap every encryption key under a new primary RSA key pair

	@param ctx context.Context - execution context
	@param newKEK encryption.KEKParams - the new primary RSA key pair
*/
func (r *runner) RotateKEK(ctx context.Context, newKEK encryption.KEKParams) error {
	if err := r.rotateKEK(ctx, newKEK); err != nil {
		return models.NewMaintenanceError("failed to rotate the primary RSA key pair", err, true)
	}
	return nil
}

// rotateKEK the steps of a primary RSA key pair rotation, in order
//
// Each step names the transaction it commits in, because the boundaries are what make the
// rotation resumable rather than an implementation detail of it.
func (r *runner) rotateKEK(ctx context.Context, newKEK encryption.KEKParams) error {
	// Load the new key pair before the system state moves. A key pair which can't be loaded,
	// or which is the one already in use, must fail with nothing touched.
	loaded, err := r.cryptoEngine.LoadKEK(ctx, newKEK)
	if err != nil {
		return goutils.NewRuntimeError("failed to load the new primary RSA key pair", err, true)
	}
	if loaded.ID() == r.cryptoEngine.KEKID() {
		return goutils.NewRuntimeError(
			fmt.Sprintf(
				"primary RSA key pair '%s' is the one already in use; there is nothing to rotate",
				loaded.ID(),
			),
			nil, true,
		)
	}

	// Step (a): open the rotation
	if err := r.openKEKRotation(ctx); err != nil {
		return err
	}

	// Step (b): re-wrap the keys. Record versions are untouched throughout: the associated
	// data binds an encryption key's ID, not its wrapping.
	if err := r.rewrapEncryptionKeys(ctx, loaded); err != nil {
		return err
	}

	// Step (c): close the rotation
	return r.closeKEKRotation(ctx, loaded)
}

// openKEKRotation transition the system into a primary RSA key pair rotation
//
// A system already in the rotation state is being resumed, which is not an error.
func (r *runner) openKEKRotation(ctx context.Context) error {
	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			params, err := requireState(
				dbCtx,
				dbClient,
				"rotate the primary RSA key pair",
				models.SystemStateReady,
				models.SystemStateKEKRotating,
			)
			if err != nil {
				return err
			}

			if params.State == models.SystemStateKEKRotating {
				// Resuming an interrupted rotation
				return nil
			}

			return dbClient.MarkSystemRotatingKEK(dbCtx)
		},
	); dbErr != nil {
		return goutils.NewRuntimeError(
			"failed to open the primary RSA key pair rotation", dbErr, true,
		)
	}

	return nil
}

// rewrapEncryptionKeys re-wrap every encryption key under the new primary RSA key pair
//
// One transaction, without paging: a rotation opens from READY, which holds exactly one
// encryption key, so there is nothing to page over. The engine skips the keys an
// interrupted run already converted, which is what lets this be rerun.
func (r *runner) rewrapEncryptionKeys(ctx context.Context, newKEK encryption.KEK) error {
	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			keys, err := dbClient.ListEncryptionKeys(dbCtx, db.EncryptionKeyQueryFilter{})
			if err != nil {
				return goutils.NewPersistenceError("failed to list the encryption keys", err, true)
			}

			return r.cryptoEngine.RewrapEncryptionKeys(dbCtx, keys, newKEK, dbClient)
		},
	); dbErr != nil {
		return goutils.NewRuntimeError(
			"failed to re-wrap the encryption keys", dbErr, true,
		)
	}

	return nil
}

// closeKEKRotation verify every encryption key moved, and return the system to normal
// operation
//
// The check is a comparison of recorded key pair IDs and involves no cryptography, which it
// could not perform anyway: every key is now wrapped by a key pair this runner does not
// hold.
func (r *runner) closeKEKRotation(ctx context.Context, newKEK encryption.KEK) error {
	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			keys, err := dbClient.ListEncryptionKeys(dbCtx, db.EncryptionKeyQueryFilter{})
			if err != nil {
				return goutils.NewPersistenceError("failed to list the encryption keys", err, true)
			}

			for _, key := range keys {
				if key.KekID != newKEK.ID() {
					return goutils.NewConsistencyError(
						fmt.Sprintf(
							"encryption key %s is still wrapped by primary RSA key pair '%s', not '%s'",
							key.ID, key.KekID, newKEK.ID(),
						),
						nil, true,
					)
				}
			}

			return dbClient.MarkSystemReady(dbCtx)
		},
	); dbErr != nil {
		return goutils.NewRuntimeError(
			"failed to close the primary RSA key pair rotation", dbErr, true,
		)
	}

	return nil
}
