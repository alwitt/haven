package db

import (
	"context"
	"fmt"

	"github.com/alwitt/haven/models"
	"github.com/google/uuid"
)

/*
RecordEncryptionKey record an encrypted symmetric encryption key

	@param ctx context.Context - execution context
	@param encKeyMaterial string - encrypted key material
	@returns the key entry
*/
func (d *databaseImpl) RecordEncryptionKey(
	_ context.Context, encKeyMaterial []byte,
) (models.EncryptionKey, error) {
	newEntry := encryptionKeyEntry{
		EncryptionKey: models.EncryptionKey{
			ID:             uuid.NewString(),
			EncKeyMaterial: encKeyMaterial,
			State:          models.EncryptionKeyStateActive,
		},
	}

	if err := d.validator.Struct(&newEntry); err != nil {
		return models.EncryptionKey{}, fmt.Errorf("new encryption key entry is invalid [%w]", err)
	}

	if tmp := d.db.Create(&newEntry); tmp.Error != nil {
		return models.EncryptionKey{}, fmt.Errorf(
			"new encryption key entry insert failed [%w]", tmp.Error,
		)
	}

	// Record this event
	if _, err := d.defineNewSystemEvent(
		models.SystemEventTypeNewEncryptionKey, models.SystemEventEncKeyRelated{KeyID: newEntry.ID},
	); err != nil {
		return models.EncryptionKey{}, fmt.Errorf(
			"failed to log add new encryption key audit event [%w]", err,
		)
	}

	return newEntry.EncryptionKey, nil
}

// getEncryptionKey fetch one encryption key
func (d *databaseImpl) getEncryptionKey(keyID string) (encryptionKeyEntry, error) {
	var entry encryptionKeyEntry
	err := d.db.Where("id = ?", keyID).First(&entry).Error
	return entry, err
}

/*
GetEncryptionKey fetch one encryption key

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@return key entry
*/
func (d *databaseImpl) GetEncryptionKey(
	_ context.Context, keyID string,
) (models.EncryptionKey, error) {
	entry, err := d.getEncryptionKey(keyID)
	if err != nil {
		return models.EncryptionKey{}, fmt.Errorf("failed to fetch encryption key %s [%w]", keyID, err)
	}
	return entry.EncryptionKey, nil
}

/*
ListEncryptionKeys list encryption keys

	@param ctx context.Context - execution context
	@param filters EncryptionKeyQueryFilter - entry listing filter
	@return list of keys
*/
func (d *databaseImpl) ListEncryptionKeys(
	_ context.Context, filters EncryptionKeyQueryFilter,
) ([]models.EncryptionKey, error) {
	query := d.db.Model(&encryptionKeyEntry{})

	if len(filters.TargetState) > 0 {
		query = query.Where("state in ?", filters.TargetState)
	}

	if filters.Limit != nil {
		query = query.Limit(*filters.Limit)
	}
	if filters.Offset != nil {
		query = query.Offset(*filters.Offset)
	}

	query = query.Order("created_at desc")

	var entries []encryptionKeyEntry
	if tmp := query.Find(&entries); tmp.Error != nil {
		return nil, fmt.Errorf("failed to list encryption keys [%w]", tmp.Error)
	}

	result := []models.EncryptionKey{}
	for _, entry := range entries {
		result = append(result, entry.EncryptionKey)
	}

	return result, nil
}

// updateEncKeyState update the encryption key entry state
func (d *databaseImpl) updateEncKeyState(
	keyID string, newState models.EncryptionKeyStateENUMType,
) error {
	entry, err := d.getEncryptionKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to fetch encryption key %s [%w]", keyID, err)
	}

	if entry.State == newState {
		// NOOP
		return nil
	}

	if err := entry.ValidateNextState(newState); err != nil {
		return fmt.Errorf("encryption key state change to %s not allowed [%w]", newState, err)
	}

	entry.State = newState
	if tmp := d.db.Updates(&entry); tmp.Error != nil {
		return fmt.Errorf("encryption key state change update failed [%w]", err)
	}

	// record this event
	var systemEventType models.SystemEventTypeENUMType
	switch newState {
	case models.EncryptionKeyStateActive:
		systemEventType = models.SystemEventTypeActivateEncryptionKey
	case models.EncryptionKeyStateInactive:
		systemEventType = models.SystemEventTypeDeactivateEncryptionKey
	}

	// Record this event
	if _, err := d.defineNewSystemEvent(
		systemEventType, models.SystemEventEncKeyRelated{KeyID: keyID},
	); err != nil {
		return fmt.Errorf(
			"failed to log encryption key state change audit event [%w]", err,
		)
	}

	return nil
}

/*
MarkEncryptionKeyActive mark encryption key is active

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
*/
func (d *databaseImpl) MarkEncryptionKeyActive(_ context.Context, keyID string) error {
	return d.updateEncKeyState(keyID, models.EncryptionKeyStateActive)
}

/*
MarkEncryptionKeyInactive mark encryption key is inactive

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
*/
func (d *databaseImpl) MarkEncryptionKeyInactive(_ context.Context, keyID string) error {
	return d.updateEncKeyState(keyID, models.EncryptionKeyStateInactive)
}

/*
DeleteEncryptionKey delete encryption key

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
*/
func (d *databaseImpl) DeleteEncryptionKey(_ context.Context, keyID string) error {
	entry, err := d.getEncryptionKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to fetch encryption key %s [%w]", keyID, err)
	}

	if tmp := d.db.Delete(&entry); tmp.Error != nil {
		return fmt.Errorf("failed to delete encryption key %s [%w]", keyID, err)
	}

	// Record this event
	if _, err := d.defineNewSystemEvent(
		models.SystemEventTypeDeleteEncryptionKey, models.SystemEventEncKeyRelated{KeyID: keyID},
	); err != nil {
		return fmt.Errorf(
			"failed to log encryption key state change audit event [%w]", err,
		)
	}

	return nil
}
