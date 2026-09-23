package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
	"gorm.io/gorm"
)

// CommonListEntryQueryFilter common query filter when listing data entries
type CommonListEntryQueryFilter struct {
	Limit  *int
	Offset *int
}

// SystemEventQueryFilter audit event query filter conditions
type SystemEventQueryFilter struct {
	CommonListEntryQueryFilter
	// EventTypes the specific event types to query for
	EventTypes []models.SystemEventTypeENUMType
	// EventsAfter filter for events after this timestamp
	EventsAfter *time.Time
	// EventsBefore filter for events before this timestamp
	EventsBefore *time.Time
}

// EncryptionKeyQueryFilter encryption key query filer conditions
type EncryptionKeyQueryFilter struct {
	CommonListEntryQueryFilter
	// TargetState the specific states to query for
	TargetState []models.EncryptionKeyStateENUMType
}

// RecordQueryFilter data record query filter conditions
type RecordQueryFilter struct {
	CommonListEntryQueryFilter
}

// RecordVersionQueryFilter data record version query filter conditions
type RecordVersionQueryFilter struct {
	CommonListEntryQueryFilter
	// TargetRecordID fetch only record versions related to this record
	TargetRecordID *string
	// TargetEncKeyID fetch versions related to this encryption key
	TargetEncKeyID *string
}

// Database the database handle to interacting with the data base
type Database interface {
	// ------------------------------------------------------------------------------------
	// System audit events

	/*
		ListSystemEvents list captured system events

			@param ctx context.Context - execution context
			@param filters SystemEventQueryFilter - entry listing filter
			@return list of system events
	*/
	ListSystemEvents(
		ctx context.Context, filters SystemEventQueryFilter,
	) ([]models.SystemEventAudit, error)

	// ------------------------------------------------------------------------------------
	// System parameters

	/*
		GetSystemParamEntry fetch the global singleton system parameter entry

			@param ctx context.Context - execution context
			@returns the entry
	*/
	GetSystemParamEntry(ctx context.Context) (models.SystemParams, error)

	/*
		MarkSystemReady mark the system ready for normal operation

			@param ctx context.Context - execution context
	*/
	MarkSystemReady(ctx context.Context) error

	/*
		MarkSystemRotatingDEK mark an encryption key rotation in progress

			@param ctx context.Context - execution context
	*/
	MarkSystemRotatingDEK(ctx context.Context) error

	/*
		MarkSystemRotatingKEK mark a primary RSA key pair rotation in progress

			@param ctx context.Context - execution context
	*/
	MarkSystemRotatingKEK(ctx context.Context) error

	// ------------------------------------------------------------------------------------
	// Encryption keys

	/*
		RecordEncryptionKey record an encrypted symmetric encryption key

			@param ctx context.Context - execution context
			@param encKeyMaterial string - encrypted key material
			@param kekID string - ID of the primary RSA key pair which encrypted the key material
			@returns the key entry
	*/
	RecordEncryptionKey(
		ctx context.Context, encKeyMaterial []byte, kekID string,
	) (models.EncryptionKey, error)

	/*
		GetEncryptionKey fetch one encryption key

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
			@return key entry
	*/
	GetEncryptionKey(ctx context.Context, keyID string) (models.EncryptionKey, error)

	/*
		ListEncryptionKeys list encryption keys

			@param ctx context.Context - execution context
			@param filters EncryptionKeyQueryFilter - entry listing filter
			@return list of keys
	*/
	ListEncryptionKeys(
		ctx context.Context, filters EncryptionKeyQueryFilter,
	) ([]models.EncryptionKey, error)

	/*
		UpdateEncryptionKeyWrapping re-wrap an existing encryption key under a different KEK

		The key keeps its ID, its state and every record version which references it; only
		the wrapped key material and the ID of the key pair which wrapped it change. The
		symmetric key itself is untouched, so every cipher text encrypted with it stays valid.

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
			@param encKeyMaterial []byte - the newly wrapped key material
			@param kekID string - ID of the primary RSA key pair which encrypted the key material
			@returns the updated key entry
	*/
	UpdateEncryptionKeyWrapping(
		ctx context.Context, keyID string, encKeyMaterial []byte, kekID string,
	) (models.EncryptionKey, error)

	/*
		MarkEncryptionKeyRetired mark encryption key retired, so it only decrypts

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
	*/
	MarkEncryptionKeyRetired(ctx context.Context, keyID string) error

	/*
		DeleteEncryptionKey delete encryption key

		The delete fails while any record version is still encrypted with the key.

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
	*/
	DeleteEncryptionKey(ctx context.Context, keyID string) error

	// ------------------------------------------------------------------------------------
	// Data records

	/*
		DefineNewRecord define new data record

			@param ctx context.Context - execution context
			@param name string - record name
			@returns record entry
	*/
	DefineNewRecord(ctx context.Context, name string) (models.Record, error)

	/*
		GetRecord fetch a data record by ID

			@param ctx context.Context - execution context
			@param recordID string - data record ID
			@returns record entry
	*/
	GetRecord(
		ctx context.Context, recordID string,
	) (models.Record, error)

	/*
		GetRecordByName fetch a data record by name

			@param ctx context.Context - execution context
			@param recordName string - data record name
			@returns record entry
	*/
	GetRecordByName(
		ctx context.Context, recordName string,
	) (models.Record, error)

	/*
		ListRecords list data records

			@param ctx context.Context - execution context
			@param filters RecordQueryFilter - entry listing filter
			@return list of records
	*/
	ListRecords(
		ctx context.Context, filters RecordQueryFilter,
	) ([]models.Record, error)

	/*
		DeleteRecord delete a data record

			@param ctx context.Context - execution context
			@param recordID string - data record ID
	*/
	DeleteRecord(ctx context.Context, recordID string) error

	// ------------------------------------------------------------------------------------
	// Data record versions

	/*
		DefineNewVersionForRecord define new data record version

		The caller assigns the version ID (see NewRecordVersionID) because it is bound into
		the value's AEAD associated data, so it must be fixed before the value is encrypted.

			@param ctx context.Context - execution context
			@param record models.Record - the parent data record
			@param versionID string - the ID of the new version
			@param encKey models.EncryptionKey - the encryption key that encrypted the data of
			    this version
			@param value []byte - the encrypted data of this record version
			@param nonce []byte - the encryption nonce
			@param timestamp time.Time - the timestamp of the version
			@returns record version entry
	*/
	DefineNewVersionForRecord(
		ctx context.Context,
		record models.Record,
		versionID string,
		encKey models.EncryptionKey,
		value []byte,
		nonce []byte,
		timestamp time.Time,
	) (models.RecordVersion, error)

	/*
		GetRecordVersion fetch a record version by ID

			@param ctx context.Context - execution context
			@param versionID string - data record version ID
			@returns record version entry
	*/
	GetRecordVersion(
		ctx context.Context, versionID string,
	) (models.RecordVersion, error)

	/*
		UpdateRecordVersionEncryption replace the encrypted payload of an existing record version

		This re-encrypts a version in place during an encryption key rotation: the version
		keeps its ID, its parent record and its place in the record's history, and only the
		encryption columns change.

			@param ctx context.Context - execution context
			@param versionID string - data record version ID
			@param encKey models.EncryptionKey - the encryption key which encrypted the new value
			@param value []byte - the newly encrypted data of this record version
			@param nonce []byte - the new encryption nonce
			@returns the updated record version entry
	*/
	UpdateRecordVersionEncryption(
		ctx context.Context,
		versionID string,
		encKey models.EncryptionKey,
		value []byte,
		nonce []byte,
	) (models.RecordVersion, error)

	/*
		PurgeRecordVersion destroy one record version

		This is the only way a version is removed without its record being removed with it.
		It exists for versions an encryption key rotation cannot decrypt.

			@param ctx context.Context - execution context
			@param versionID string - data record version ID
	*/
	PurgeRecordVersion(ctx context.Context, versionID string) error

	/*
		ListAllRecordVersions list data record versions

			@param ctx context.Context - execution context
			@param filters RecordVersionQueryFilter - entry listing filter
			@return list of record versions
	*/
	ListAllRecordVersions(
		ctx context.Context, filters RecordVersionQueryFilter,
	) ([]models.RecordVersion, error)

	/*
		CountRecordVersions count the data record versions matching a filter

		The filter's Limit and Offset are ignored: the count of one page is not a useful number.

			@param ctx context.Context - execution context
			@param filters RecordVersionQueryFilter - entry counting filter
			@returns the number of matching record versions
	*/
	CountRecordVersions(ctx context.Context, filters RecordVersionQueryFilter) (int64, error)

	/*
		ListVersionsOfOneRecord list data record versions of a specific record

			@param ctx context.Context - execution context
			@param record models.Record - parent data record
			@param filters RecordVersionQueryFilter - entry listing filter
			@return list of record versions
	*/
	ListVersionsOfOneRecord(
		ctx context.Context, record models.Record, filters RecordVersionQueryFilter,
	) ([]models.RecordVersion, error)

	/*
		ListVersionsEncryptedByKey list data record versions encrypted with a specific
		encryption key

			@param ctx context.Context - execution context
			@param encKey models.EncryptionKey - the encryption key used
			@param filters RecordVersionQueryFilter - entry listing filter
			@return list of record versions
	*/
	ListVersionsEncryptedByKey(
		ctx context.Context, encKey models.EncryptionKey, filters RecordVersionQueryFilter,
	) ([]models.RecordVersion, error)
}

// databaseImpl implements Database
type databaseImpl struct {
	goutils.Component
	db        *gorm.DB
	validator *validator.Validate
}

// newDatabase define a new database client
func newDatabase(_ context.Context, sqlClient *gorm.DB) (Database, error) {
	logTags := log.Fields{"package": "haven", "module": "db", "component": "db-client"}

	instance := &databaseImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
			},
		},
		db:        sqlClient,
		validator: validator.New(),
	}

	if err := models.RegisterWithValidator(instance.validator); err != nil {
		return nil, goutils.NewRuntimeError("failed to install custom validation macros", err, true)
	}

	return instance, nil
}

// notFoundOrError translates the error returned by a single-entry fetch into a
// goutils.NotFoundError when GORM reports that the record does not exist. Any other
// error is returned unchanged, and a nil error stays nil.
func notFoundOrError(err error, entity, id string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return goutils.NewNotFoundError(
			fmt.Sprintf("%s '%s' does not exist", entity, id), err, true,
		)
	}
	return goutils.NewSQLError(fmt.Sprintf("failed to fetch %s '%s'", entity, id), err, true)
}
