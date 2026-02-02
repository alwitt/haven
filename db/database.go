package db

import (
	"context"
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
		MarkSystemInitializing mark system is initializing

			@param ctx context.Context - execution context
	*/
	MarkSystemInitializing(ctx context.Context) error

	/*
		MarkSystemInitializing mark system fully initialized

			@param ctx context.Context - execution context
	*/
	MarkSystemInitialized(ctx context.Context) error

	// ------------------------------------------------------------------------------------
	// Encryption keys

	/*
		RecordEncryptionKey record an encrypted symmetric encryption key

			@param ctx context.Context - execution context
			@param encKeyMaterial string - encrypted key material
			@returns the key entry
	*/
	RecordEncryptionKey(ctx context.Context, encKeyMaterial []byte) (models.EncryptionKey, error)

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
		MarkEncryptionKeyActive mark encryption key is active

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
	*/
	MarkEncryptionKeyActive(ctx context.Context, keyID string) error

	/*
		MarkEncryptionKeyInactive mark encryption key is inactive

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
	*/
	MarkEncryptionKeyInactive(ctx context.Context, keyID string) error

	/*
		DeleteEncryptionKey delete encryption key

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

			@param ctx context.Context - execution context
			@param record models.Record - the parent data record
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
		ListAllRecordVersions list data record versions

			@param ctx context.Context - execution context
			@param filters RecordVersionQueryFilter - entry listing filter
			@return list of record versions
	*/
	ListAllRecordVersions(
		ctx context.Context, filters RecordVersionQueryFilter,
	) ([]models.RecordVersion, error)

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
		return nil, fmt.Errorf("failed to install custom validation macros [%w]", err)
	}

	return instance, nil
}
