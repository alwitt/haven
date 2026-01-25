package db

import (
	"context"
	"fmt"
	"time"

	"github.com/alwitt/haven/models"
	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
)

// ======================================================================================
// Data records

/*
DefineNewRecord define new data record

	@param ctx context.Context - execution context
	@param name string - record name
	@returns record entry
*/
func (d *databaseImpl) DefineNewRecord(_ context.Context, name string) (models.Record, error) {
	newEntry := recordEntry{
		Record: models.Record{
			ID:   uuid.NewString(),
			Name: name,
		},
	}

	if err := d.validator.Struct(&newEntry); err != nil {
		return models.Record{}, fmt.Errorf("new record '%s' is not valid [%w]", name, err)
	}

	if tmp := d.db.Create(&newEntry); tmp.Error != nil {
		return models.Record{}, fmt.Errorf("new record '%s' failed insert [%w]", name, tmp.Error)
	}

	// Record this event
	if _, err := d.defineNewSystemEvent(
		models.SystemEventTypeAddNewRecord,
		models.SystemEventDataRecordRelated{RecordID: newEntry.ID, RecordName: name},
	); err != nil {
		return models.Record{}, fmt.Errorf(
			"failed to log add new record '%s' audit event [%w]", name, err,
		)
	}

	return newEntry.Record, nil
}

// getRecordEntry find a data record by ID
func (d *databaseImpl) getRecordEntry(recordID string) (recordEntry, error) {
	var entry recordEntry
	err := d.db.Where("id = ?", recordID).First(&entry).Error
	return entry, err
}

/*
GetRecord fetch a data record by ID

	@param ctx context.Context - execution context
	@param recordID string - data record ID
	@returns record entry
*/
func (d *databaseImpl) GetRecord(
	_ context.Context, recordID string,
) (models.Record, error) {
	entry, err := d.getRecordEntry(recordID)
	if err != nil {
		return models.Record{}, fmt.Errorf("failed to fetch record %s [%w]", recordID, err)
	}

	return entry.Record, nil
}

/*
GetRecordByName fetch a data record by name

	@param ctx context.Context - execution context
	@param recordName string - data record name
	@returns record entry
*/
func (d *databaseImpl) GetRecordByName(
	_ context.Context, recordName string,
) (models.Record, error) {
	var entry recordEntry
	if tmp := d.db.Where("name = ?", recordName).First(&entry); tmp.Error != nil {
		return models.Record{}, fmt.Errorf("failed to fetch record '%s' [%w]", recordName, tmp.Error)
	}

	return entry.Record, nil
}

/*
ListRecords list data records

	@param ctx context.Context - execution context
	@param filters RecordQueryFilter - entry listing filter
	@return list of records
*/
func (d *databaseImpl) ListRecords(
	_ context.Context, filters RecordQueryFilter,
) ([]models.Record, error) {
	query := d.db.Model(&recordEntry{})

	if filters.Limit != nil {
		query = query.Limit(*filters.Limit)
	}
	if filters.Offset != nil {
		query = query.Offset(*filters.Offset)
	}

	query = query.Order("created_at desc")

	var entries []recordEntry
	if tmp := query.Find(&entries); tmp.Error != nil {
		return nil, fmt.Errorf("failed to list data records [%w]", tmp.Error)
	}

	result := []models.Record{}
	for _, entry := range entries {
		result = append(result, entry.Record)
	}

	return result, nil
}

/*
DeleteRecord delete a data record

	@param ctx context.Context - execution context
	@param recordID string - data record ID
*/
func (d *databaseImpl) DeleteRecord(_ context.Context, recordID string) error {
	entry, err := d.getRecordEntry(recordID)
	if err != nil {
		return fmt.Errorf("failed to fetch record %s [%w]", recordID, err)
	}

	if tmp := d.db.Delete(&entry); tmp.Error != nil {
		return fmt.Errorf("failed to delete record %s [%w]", recordID, tmp.Error)
	}

	// Record this event
	if _, err := d.defineNewSystemEvent(
		models.SystemEventTypeDeleteRecord,
		models.SystemEventDataRecordRelated{RecordID: entry.ID, RecordName: entry.Name},
	); err != nil {
		return fmt.Errorf(
			"failed to log delete record '%s' audit event [%w]", entry.Name, err,
		)
	}

	return nil
}

// ======================================================================================
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
func (d *databaseImpl) DefineNewVersionForRecord(
	_ context.Context,
	record models.Record,
	encKey models.EncryptionKey,
	value []byte,
	nonce []byte,
	timestamp time.Time,
) (models.RecordVersion, error) {
	newEntry := recordVersionEntry{
		RecordVersion: models.RecordVersion{
			ID:        ulid.Make().String(),
			RecordID:  record.ID,
			EncKeyID:  encKey.ID,
			EncValue:  value,
			EncNonce:  nonce,
			CreatedAt: timestamp,
			UpdatedAt: timestamp,
		},
	}

	if err := d.validator.Struct(&newEntry); err != nil {
		return models.RecordVersion{}, fmt.Errorf(
			"new version for record %s is invalid [%w]", record.ID, err,
		)
	}

	if tmp := d.db.Create(&newEntry); tmp.Error != nil {
		return models.RecordVersion{}, fmt.Errorf(
			"new version for record %s insert failed [%w]", record.ID, tmp.Error,
		)
	}

	return newEntry.RecordVersion, nil
}

/*
GetRecordVersion fetch a record version by ID

	@param ctx context.Context - execution context
	@param versionID string - data record version ID
	@returns record version entry
*/
func (d *databaseImpl) GetRecordVersion(
	_ context.Context, versionID string,
) (models.RecordVersion, error) {
	var entry recordVersionEntry
	if tmp := d.db.Where("id = ?", versionID).First(&entry); tmp.Error != nil {
		return models.RecordVersion{}, fmt.Errorf(
			"failed to fetch record version %s [%w]", versionID, tmp.Error,
		)
	}

	return entry.RecordVersion, nil
}

/*
ListAllRecordVersions list data record versions

	@param ctx context.Context - execution context
	@param filters RecordVersionQueryFilter - entry listing filter
	@return list of record versions
*/
func (d *databaseImpl) ListAllRecordVersions(
	_ context.Context, filters RecordVersionQueryFilter,
) ([]models.RecordVersion, error) {
	query := d.db.Model(&recordVersionEntry{})

	if filters.TargetRecordID != nil {
		query = query.Where("record_id = ?", *filters.TargetRecordID)
	}

	if filters.TargetEncKeyID != nil {
		query = query.Where("enc_key_id = ?", *filters.TargetEncKeyID)
	}

	if filters.Limit != nil {
		query = query.Limit(*filters.Limit)
	}
	if filters.Offset != nil {
		query = query.Offset(*filters.Offset)
	}

	query = query.Order("created_at desc")

	var entries []recordVersionEntry
	if tmp := query.Find(&entries); tmp.Error != nil {
		return nil, fmt.Errorf("failed to list data record versions [%w]", tmp.Error)
	}

	result := []models.RecordVersion{}
	for _, entry := range entries {
		result = append(result, entry.RecordVersion)
	}

	return result, nil
}

/*
ListVersionsOfOneRecord list data record versions of a specific record

	@param ctx context.Context - execution context
	@param record models.Record - parent data record
	@param filters RecordVersionQueryFilter - entry listing filter
	@return list of record versions
*/
func (d *databaseImpl) ListVersionsOfOneRecord(
	ctx context.Context, record models.Record, filters RecordVersionQueryFilter,
) ([]models.RecordVersion, error) {
	filters.TargetRecordID = &record.ID
	return d.ListAllRecordVersions(ctx, filters)
}

/*
ListVersionsEncryptedByKey list data record versions encrypted with a specific
encryption key

	@param ctx context.Context - execution context
	@param encKey models.EncryptionKey - the encryption key used
	@param filters RecordVersionQueryFilter - entry listing filter
	@return list of record versions
*/
func (d *databaseImpl) ListVersionsEncryptedByKey(
	ctx context.Context, encKey models.EncryptionKey, filters RecordVersionQueryFilter,
) ([]models.RecordVersion, error) {
	filters.TargetEncKeyID = &encKey.ID
	return d.ListAllRecordVersions(ctx, filters)
}
