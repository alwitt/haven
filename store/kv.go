// Package store - data storage controllers
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
)

// ProtectedKVStore protected key store record KVs after encrypting value
type ProtectedKVStore interface {
	/*
		RecordKeyValue record a key value pair

			@param ctx context.Context - execution context
			@param key string - key
			@param value []byte - value
			@param timestamp time.Time - record timestamp
			@param activeDBClient Database - existing database transaction
			@returns the record and record version entry
	*/
	RecordKeyValue(
		ctx context.Context, key string, value []byte, timestamp time.Time, activeDBClient db.Database,
	) (models.Record, models.RecordVersion, error)

	/*
		ListKeyVersions list the versions of a key

			@param ctx context.Context - execution context
			@param key string - key
			@param activeDBClient Database - existing database transaction
			@returns the record and its associated versions
	*/
	ListKeyVersions(
		ctx context.Context, key string, activeDBClient db.Database,
	) (models.Record, []models.RecordVersion, error)

	/*
		GetValueOfKeyAtVersionID get the value of a key at a particular version by ID

			@param ctx context.Context - execution context
			@param versionID string - the version ID
			@param activeDBClient Database - existing database transaction
			@return decrypted value of that version
	*/
	GetValueOfKeyAtVersionID(
		ctx context.Context, versionID string, activeDBClient db.Database,
	) ([]byte, error)

	/*
		GetValueOfKeyAtVersion get the value of a key at particular version

			@param ctx context.Context - execution context
			@param versionEntry models.RecordVersion - the version
			@param activeDBClient Database - existing database transaction
			@return decrypted value of that version
	*/
	GetValueOfKeyAtVersion(
		ctx context.Context, versionEntry models.RecordVersion, activeDBClient db.Database,
	) ([]byte, error)

	/*
		DeleteKey delete a key from storage

			@param ctx context.Context - execution context
			@param key string - key
			@param activeDBClient Database - existing database transaction
	*/
	DeleteKey(ctx context.Context, key string, activeDBClient db.Database) error
}

// protectedKVStore implements ProtectedKVStore
type protectedKVStore struct {
	goutils.Component

	persistence db.Client

	cryptoEngine encryption.CryptographyEngine

	workingKey models.EncryptionKey
}

/*
NewProtectedKVStore define new protected KV store

	@param ctx context.Context - execution context
	@param persistence db.Client - persistence layer client
	@param cryptoEngine encryption.CryptographyEngine - cryptography engine
	@returns store instance
*/
func NewProtectedKVStore(
	ctx context.Context, persistence db.Client, cryptoEngine encryption.CryptographyEngine,
) (ProtectedKVStore, error) {
	logTags := log.Fields{"module": "store", "component": "protected-kv-store"}

	instance := &protectedKVStore{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
			},
		},
		persistence:  persistence,
		cryptoEngine: cryptoEngine,
	}

	// Prepare the working encryption key
	if dbErr := persistence.UseDatabaseInTransaction(
		ctx, func(dbCtx context.Context, dbClient db.Database) error {
			activeKeys, err := cryptoEngine.ListEncryptionKeys(
				dbCtx,
				db.EncryptionKeyQueryFilter{
					TargetState: []models.EncryptionKeyStateENUMType{models.EncryptionKeyStateActive},
				},
				dbClient,
			)
			if err != nil {
				return fmt.Errorf("failed to list active encryption keys [%w]", err)
			}

			if len(activeKeys) == 0 {
				// Make a new key
				instance.workingKey, err = cryptoEngine.NewEncryptionKey(dbCtx, dbClient)
				if err != nil {
					return fmt.Errorf("failed to define new encryption key [%w]", err)
				}
			} else {
				// Use the newest key
				instance.workingKey = activeKeys[0]
			}

			return nil
		},
	); dbErr != nil {
		return nil, fmt.Errorf("failed to prepare working encryption key [%w]", dbErr)
	}

	return instance, nil
}

/*
RecordKeyValue record a key value pair

	@param ctx context.Context - execution context
	@param key string - key
	@param value []byte - value
	@param timestamp time.Time - record timestamp
	@param activeDBClient Database - existing database transaction
	@returns the record and record version entry
*/
func (s *protectedKVStore) RecordKeyValue(
	ctx context.Context, key string, value []byte, timestamp time.Time, activeDBClient db.Database,
) (models.Record, models.RecordVersion, error) {
	var recordEntry models.Record
	var versionEntry models.RecordVersion

	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, s.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			var err error

			// Prepare data record
			recordEntry, err = dbClient.GetRecordByName(dbCtx, key)
			if err != nil {
				// Make a new record
				recordEntry, err = dbClient.DefineNewRecord(dbCtx, key)
				if err != nil {
					return fmt.Errorf("failed to define new data record [%w]", err)
				}
			}

			// Encrypt the data
			theKey, encrypted, err := s.cryptoEngine.EncryptData(dbCtx, s.workingKey.ID, value, dbClient)
			if err != nil {
				return fmt.Errorf("failed to encryption record value [%w]", err)
			}

			// Prepare new version
			versionEntry, err = dbClient.DefineNewVersionForRecord(
				dbCtx, recordEntry, theKey, encrypted.CipherText, encrypted.Nonce, timestamp,
			)
			if err != nil {
				return fmt.Errorf("failed to insert new record version [%w]", err)
			}

			return nil
		},
	); dbErr != nil {
		return models.Record{},
			models.RecordVersion{},
			fmt.Errorf("failed to record key '%s' [%w]", key, dbErr)
	}

	return recordEntry, versionEntry, nil
}

/*
ListKeyVersions list the versions of a key

	@param ctx context.Context - execution context
	@param key string - key
	@param activeDBClient Database - existing database transaction
	@returns the record and its associated versions
*/
func (s *protectedKVStore) ListKeyVersions(
	ctx context.Context, key string, activeDBClient db.Database,
) (models.Record, []models.RecordVersion, error) {
	var recordEntry models.Record
	var versionEntries []models.RecordVersion

	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, s.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			var err error

			// Prepare data record
			recordEntry, err = dbClient.GetRecordByName(dbCtx, key)
			if err != nil {
				return fmt.Errorf("failed to find key '%s' [%w]", key, err)
			}

			versionEntries, err = dbClient.ListVersionsOfOneRecord(
				dbCtx, recordEntry, db.RecordVersionQueryFilter{},
			)
			if err != nil {
				return fmt.Errorf("failed to list key %s versions [%w]", recordEntry.ID, err)
			}

			return nil
		},
	); dbErr != nil {
		return models.Record{}, nil, fmt.Errorf("failed to list key '%s' versions [%w]", key, dbErr)
	}

	return recordEntry, versionEntries, nil
}

/*
GetValueOfKeyAtVersionID get the value of a key at a particular version by ID

	@param ctx context.Context - execution context
	@param versionID string - the version ID
	@param activeDBClient Database - existing database transaction
	@return decrypted value of that version
*/
func (s *protectedKVStore) GetValueOfKeyAtVersionID(
	ctx context.Context, versionID string, activeDBClient db.Database,
) ([]byte, error) {
	var versionEntry models.RecordVersion

	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, s.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			var err error
			versionEntry, err = dbClient.GetRecordVersion(dbCtx, versionID)
			return err
		},
	); dbErr != nil {
		return nil, fmt.Errorf("failed to find key version %s [%w]", versionID, dbErr)
	}

	// Decrypt the value
	_, plainText, err := s.cryptoEngine.DecryptData(
		ctx, versionEntry.EncKeyID, encryption.EncryptedData{
			CipherText: versionEntry.EncValue, Nonce: versionEntry.EncNonce,
		}, activeDBClient,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key version %s [%w]", versionID, err)
	}

	return plainText, nil
}

/*
GetValueOfKeyAtVersion get the value of a key at particular version

	@param ctx context.Context - execution context
	@param versionEntry models.RecordVersion - the version
	@param activeDBClient Database - existing database transaction
	@return decrypted value of that version
*/
func (s *protectedKVStore) GetValueOfKeyAtVersion(
	ctx context.Context, versionEntry models.RecordVersion, activeDBClient db.Database,
) ([]byte, error) {
	// Decrypt the value
	_, plainText, err := s.cryptoEngine.DecryptData(
		ctx, versionEntry.EncKeyID, encryption.EncryptedData{
			CipherText: versionEntry.EncValue, Nonce: versionEntry.EncNonce,
		}, activeDBClient,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key version %s [%w]", versionEntry.ID, err)
	}

	return plainText, nil
}

/*
DeleteKey delete a key from storage

	@param ctx context.Context - execution context
	@param key string - key
	@param activeDBClient Database - existing database transaction
*/
func (s *protectedKVStore) DeleteKey(
	ctx context.Context, key string, activeDBClient db.Database,
) error {
	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, s.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			// Prepare data record
			recordEntry, err := dbClient.GetRecordByName(dbCtx, key)
			if err != nil {
				return fmt.Errorf("failed to find key '%s' [%w]", key, err)
			}

			return dbClient.DeleteRecord(dbCtx, recordEntry.ID)
		},
	); dbErr != nil {
		return fmt.Errorf("failed to delete key '%s' versions [%w]", key, dbErr)
	}

	return nil
}
