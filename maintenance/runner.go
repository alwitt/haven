// Package maintenance - operations which change the system's cryptographic material
package maintenance

import (
	"context"
	"fmt"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
)

// defaultPageSize how many entries a maintenance action converts per transaction
const defaultPageSize = 100

/*
Runner performs the maintenance actions which change the system's cryptographic material.

An action owns its transaction structure, which is why none of these methods accept an
existing database transaction. The transition which opens a rotation is committed on its
own, before any work starts, specifically so the persistence layer can refuse record writes
for the rotation's whole duration; an action running inside a caller's transaction would
hide that barrier until the end, and leave nothing committed for an interrupted action to
resume from.

No instance of the embedding application may run while an action is in progress. `haven`
cannot coordinate across processes, so this is a requirement on the operator. The guard
rails in the persistence layer bound the damage when it is broken; they do not make
breaking it safe.
*/
type Runner interface {
	/*
		Status report the system's cryptographic state and any outstanding maintenance work

			@param ctx context.Context - execution context
			@returns the status report
	*/
	Status(ctx context.Context) (Status, error)

	/*
		Initialize prepare a system for normal operation

		Mints the first encryption key and opens the record data API. This is deliberately
		not done when a KV store is constructed: two application instances starting against
		an empty database would race, and both would mint a key.

			@param ctx context.Context - execution context
	*/
	Initialize(ctx context.Context) error

	/*
		RotateEncryptionKey replace the encryption key, and move every record version onto it

		The old key is retired while its data is moved, then deleted. An interrupted rotation
		is resumed by calling this again; it rolls forward only, and must be run to
		completion.

			@param ctx context.Context - execution context
	*/
	RotateEncryptionKey(ctx context.Context) error

	/*
		RotateKEK re-wrap every encryption key under a new primary RSA key pair

		Record versions are untouched: the associated data binds an encryption key's ID, not
		its wrapping, so re-wrapping leaves every cipher text valid. Once this completes the
		application must be restarted with the new key pair configured.

			@param ctx context.Context - execution context
			@param newKEK encryption.KEKParams - the new primary RSA key pair
	*/
	RotateKEK(ctx context.Context, newKEK encryption.KEKParams) error

	/*
		ListUndecryptableVersions report the record versions an encryption key rotation
		cannot convert

		Read only. A rotation halts on the first version it cannot decrypt, so this is how an
		operator learns the full extent of the damage before choosing between restoring the
		rows from a backup and destroying them.

			@param ctx context.Context - execution context
			@returns one entry per version which will not decrypt
	*/
	ListUndecryptableVersions(ctx context.Context) ([]UndecryptableVersion, error)

	/*
		PurgeUndecryptableVersions destroy the record versions an encryption key rotation
		cannot convert

		Destructive and unrecoverable. Every version destroyed is audited individually,
		because the audit event is the only record that the data ever existed.

			@param ctx context.Context - execution context
			@returns one entry per version destroyed
	*/
	PurgeUndecryptableVersions(ctx context.Context) ([]UndecryptableVersion, error)
}

// Status a report of the system's cryptographic state and any outstanding maintenance work
type Status struct {
	// State the current system state
	State models.SystemStateENUMType
	// KEKID the ID of the primary RSA key pair this runner holds
	KEKID string
	// ActiveKeys the encryption keys which encrypt new data
	ActiveKeys []models.EncryptionKey
	// RetiredKeys the encryption keys which only decrypt. Any at all means an encryption key
	// rotation is incomplete.
	RetiredKeys []models.EncryptionKey
	// VersionsUnderRetiredKeys how many record versions an encryption key rotation still has
	// to move
	VersionsUnderRetiredKeys int64
	// KeysUnderAnotherKEK how many encryption keys a KEK rotation still has to re-wrap
	KeysUnderAnotherKEK int
	// ReadyInvariantHolds whether the system holds exactly one active key and no retired
	// ones, which is what a state of READY means
	ReadyInvariantHolds bool
}

// UndecryptableVersion a record version an encryption key rotation cannot convert
type UndecryptableVersion struct {
	// Version the record version which will not decrypt
	Version models.RecordVersion
	// RecordName the name of the record the version belongs to
	RecordName string
	// Cause the underlying authentication failure
	Cause error
}

// runner implements Runner
type runner struct {
	goutils.Component

	persistence  db.Client
	cryptoEngine encryption.CryptographyEngine

	pageSize int
}

/*
NewRunner define a new maintenance action runner

The runner is constructed with the primary RSA key pair currently in use, by way of the
cryptography engine. It deliberately performs no state check: repairing a system left in a
rotation state is the reason it exists.

	@param ctx context.Context - execution context
	@param persistence db.Client - persistence layer client
	@param cryptoEngine encryption.CryptographyEngine - cryptography engine
	@param pageSize int - how many entries to convert per transaction. Defaults when <= 0.
	@returns runner instance
*/
func NewRunner(
	_ context.Context,
	persistence db.Client,
	cryptoEngine encryption.CryptographyEngine,
	pageSize int,
) (Runner, error) {
	logTags := log.Fields{
		"package": "haven", "module": "maintenance", "component": "maintenance-runner",
	}

	if pageSize <= 0 {
		pageSize = defaultPageSize
	}

	instance := &runner{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
			},
		},
		persistence:  persistence,
		cryptoEngine: cryptoEngine,
		pageSize:     pageSize,
	}

	return instance, nil
}

/*
Status report the system's cryptographic state and any outstanding maintenance work

	@param ctx context.Context - execution context
	@returns the status report
*/
func (r *runner) Status(ctx context.Context) (Status, error) {
	report := Status{KEKID: r.cryptoEngine.KEKID()}

	if dbErr := r.persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			params, err := dbClient.GetSystemParamEntry(dbCtx)
			if err != nil {
				return err
			}
			report.State = params.State

			keys, err := dbClient.ListEncryptionKeys(dbCtx, db.EncryptionKeyQueryFilter{})
			if err != nil {
				return err
			}

			for _, key := range keys {
				if key.KekID != report.KEKID {
					report.KeysUnderAnotherKEK++
				}

				switch key.State {
				case models.EncryptionKeyStateActive:
					report.ActiveKeys = append(report.ActiveKeys, key)
				case models.EncryptionKeyStateRetired:
					report.RetiredKeys = append(report.RetiredKeys, key)

					count, err := dbClient.CountRecordVersions(
						dbCtx, db.RecordVersionQueryFilter{TargetEncKeyID: &key.ID},
					)
					if err != nil {
						return err
					}
					report.VersionsUnderRetiredKeys += count
				}
			}

			return nil
		},
	); dbErr != nil {
		return Status{}, models.NewMaintenanceError("failed to read the system status", dbErr, true)
	}

	// A state of READY means exactly one key encrypts, and nothing is left half moved
	report.ReadyInvariantHolds = len(report.ActiveKeys) == 1 && len(report.RetiredKeys) == 0

	return report, nil
}

// requireState refuse an action unless the system is in one of the given states
//
// The error names the state the system is actually in, because an operator reading
// "a maintenance action must be completed" without knowing which one has nothing to act on.
func requireState(
	dbCtx context.Context,
	dbClient db.Database,
	action string,
	permitted ...models.SystemStateENUMType,
) (models.SystemParams, error) {
	params, err := dbClient.GetSystemParamEntry(dbCtx)
	if err != nil {
		return models.SystemParams{}, goutils.NewPersistenceError(
			"failed to read the system parameter entry", err, true,
		)
	}

	for _, state := range permitted {
		if params.State == state {
			return params, nil
		}
	}

	return models.SystemParams{}, goutils.NewRuntimeError(
		fmt.Sprintf("can't %s while the system is in state '%s'", action, params.State), nil, true,
	)
}

// listKeysInState list the encryption keys in one state
func listKeysInState(
	dbCtx context.Context, dbClient db.Database, state models.EncryptionKeyStateENUMType,
) ([]models.EncryptionKey, error) {
	keys, err := dbClient.ListEncryptionKeys(dbCtx, db.EncryptionKeyQueryFilter{
		TargetState: []models.EncryptionKeyStateENUMType{state},
	})
	if err != nil {
		return nil, goutils.NewPersistenceError(
			fmt.Sprintf("failed to list '%s' encryption keys", state), err, true,
		)
	}
	return keys, nil
}
