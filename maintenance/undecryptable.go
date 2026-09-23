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
ListUndecryptableVersions report the record versions an encryption key rotation cannot
convert

	@param ctx context.Context - execution context
	@returns one entry per version which will not decrypt
*/
func (r *runner) ListUndecryptableVersions(ctx context.Context) ([]UndecryptableVersion, error) {
	findings, err := r.scanRetiredKeys(ctx, false)
	if err != nil {
		return nil, models.NewMaintenanceError(
			"failed to list the undecryptable record versions", err, true,
		)
	}
	return findings, nil
}

/*
PurgeUndecryptableVersions destroy the record versions an encryption key rotation cannot
convert

	@param ctx context.Context - execution context
	@returns one entry per version destroyed
*/
func (r *runner) PurgeUndecryptableVersions(ctx context.Context) ([]UndecryptableVersion, error) {
	findings, err := r.scanRetiredKeys(ctx, true)
	if err != nil {
		return nil, models.NewMaintenanceError(
			"failed to purge the undecryptable record versions", err, true,
		)
	}
	return findings, nil
}

/*
scanRetiredKeys find, and optionally destroy, the record versions under a retired
encryption key which will not decrypt

Both forms are restricted to a system in an encryption key rotation. Outside one there are
no retired keys, so the scan has no scope; and a version which will not decrypt under the
active key blocks nothing, so destroying it has no forcing function.

	@param ctx context.Context - execution context
	@param purge bool - whether to destroy what is found
	@returns one entry per version which will not decrypt
*/
func (r *runner) scanRetiredKeys(ctx context.Context, purge bool) ([]UndecryptableVersion, error) {
	action := "list the undecryptable record versions"
	if purge {
		action = "purge the undecryptable record versions"
	}

	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			_, err := requireState(dbCtx, dbClient, action, models.SystemStateDEKRotating)
			return err
		},
	); dbErr != nil {
		return nil, dbErr
	}

	retired, err := r.retiredKeys(ctx)
	if err != nil {
		return nil, err
	}

	findings := []UndecryptableVersion{}
	for _, key := range retired {
		keyFindings, err := r.scanOneKey(ctx, key, purge)
		if err != nil {
			return nil, goutils.NewRuntimeError(
				fmt.Sprintf("failed to %s under encryption key %s", action, key.ID), err, true,
			)
		}
		findings = append(findings, keyFindings...)
	}

	return findings, nil
}

// scanOneKey find, and optionally destroy, the versions under one encryption key which will
// not decrypt
//
// Unlike the rotation drain, this does not change the column it selects on: it removes some
// rows and keeps the rest, so the result set never empties and a loop requesting the first
// page forever would spin on the rows it keeps. The offset therefore advances by the number
// of versions kept, stepping past exactly the ones left behind.
func (r *runner) scanOneKey(
	ctx context.Context, sourceKey models.EncryptionKey, purge bool,
) ([]UndecryptableVersion, error) {
	findings := []UndecryptableVersion{}
	offset := 0

	for {
		pageSize := r.pageSize
		pageOffset := offset

		var kept int
		var pageLen int

		if err := r.persistence.UseDatabaseInTransaction(
			ctx, func(dbCtx context.Context, dbClient db.Database) error {
				batch, err := dbClient.ListVersionsEncryptedByKey(
					dbCtx,
					sourceKey,
					db.RecordVersionQueryFilter{
						CommonListEntryQueryFilter: db.CommonListEntryQueryFilter{
							Limit: &pageSize, Offset: &pageOffset,
						},
					},
				)
				if err != nil {
					return goutils.NewPersistenceError("failed to list the record versions", err, true)
				}

				pageLen = len(batch)
				if pageLen == 0 {
					return nil
				}

				failures, err := r.cryptoEngine.FindUndecryptableVersions(dbCtx, batch, dbClient)
				if err != nil {
					return err
				}

				// Everything the scan could read stays where it is
				kept = pageLen - len(failures)

				pageFindings, err := r.describeFailures(dbCtx, dbClient, failures)
				if err != nil {
					return err
				}
				findings = append(findings, pageFindings...)

				if !purge {
					return nil
				}

				for _, failure := range failures {
					if err := dbClient.PurgeRecordVersion(dbCtx, failure.Version.ID); err != nil {
						return goutils.NewPersistenceError(
							fmt.Sprintf("failed to purge record version %s", failure.Version.ID),
							err, true,
						)
					}
				}

				return nil
			},
		); err != nil {
			return nil, err
		}

		if pageLen == 0 {
			return findings, nil
		}

		if purge {
			offset += kept
		} else {
			// Nothing was removed, so the whole page is behind us
			offset += pageLen
		}
	}
}

// describeFailures join the name of the record each failing version belongs to
//
// The cryptography engine reports the row and the cause; the record name is not its to
// fetch.
func (r *runner) describeFailures(
	dbCtx context.Context, dbClient db.Database, failures []encryption.UndecryptableVersion,
) ([]UndecryptableVersion, error) {
	described := []UndecryptableVersion{}

	for _, failure := range failures {
		record, err := dbClient.GetRecord(dbCtx, failure.Version.RecordID)
		if err != nil {
			return nil, goutils.NewPersistenceError(
				fmt.Sprintf("failed to fetch record %s", failure.Version.RecordID), err, true,
			)
		}

		described = append(described, UndecryptableVersion{
			Version: failure.Version, RecordName: record.Name, Cause: failure.Cause,
		})
	}

	return described, nil
}
