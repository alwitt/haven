package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/models"
	"github.com/google/uuid"
	"gorm.io/gorm"
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
	newEntry := EncryptionKeyDBEntry{
		EncryptionKey: models.EncryptionKey{
			ID:             uuid.NewString(),
			EncKeyMaterial: encKeyMaterial,
			State:          models.EncryptionKeyStateActive,
		},
	}

	if err := d.validator.Struct(&newEntry); err != nil {
		return models.EncryptionKey{}, goutils.NewValidationError(
			"new encryption key entry is invalid", err, true,
		)
	}

	if tmp := d.db.Create(&newEntry); tmp.Error != nil {
		return models.EncryptionKey{}, models.NewSQLError(
			"new encryption key entry insert failed", tmp.Error, true,
		)
	}

	// Record this event
	if _, err := d.defineNewSystemEvent(
		models.SystemEventTypeNewEncryptionKey, models.SystemEventEncKeyRelated{KeyID: newEntry.ID},
	); err != nil {
		return models.EncryptionKey{}, goutils.NewRuntimeError(
			"failed to log add new encryption key audit event", err, true,
		)
	}

	return newEntry.EncryptionKey, nil
}

// getEncryptionKey fetch one encryption key
func (d *databaseImpl) getEncryptionKey(keyID string) (EncryptionKeyDBEntry, error) {
	var entry EncryptionKeyDBEntry
	if err := d.db.Where("id = ?", keyID).First(&entry).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return entry, goutils.NewNotFoundError(
				fmt.Sprintf("encryption key %s does not exist", keyID), err, true,
			)
		}
		return entry, models.NewSQLError(
			fmt.Sprintf("failed to fetch encryption key %s", keyID), err, true,
		)
	}
	return entry, nil
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
		return models.EncryptionKey{}, goutils.NewRuntimeError(
			fmt.Sprintf("failed to fetch encryption key %s", keyID), err, true,
		)
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
	query := d.db.Model(&EncryptionKeyDBEntry{})

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

	var entries []EncryptionKeyDBEntry
	if tmp := query.Find(&entries); tmp.Error != nil {
		return nil, models.NewSQLError("failed to list encryption keys", tmp.Error, true)
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
		return goutils.NewRuntimeError(
			fmt.Sprintf("failed to fetch encryption key %s", keyID), err, true,
		)
	}

	if entry.State == newState {
		// NOOP
		return nil
	}

	if err := entry.ValidateNextState(newState); err != nil {
		return err
	}

	entry.State = newState
	if tmp := d.db.Updates(&entry); tmp.Error != nil {
		return models.NewSQLError("encryption key state change update failed", tmp.Error, true)
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
		return goutils.NewRuntimeError(
			"failed to log encryption key state change audit event", err, true,
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
		return goutils.NewRuntimeError(
			fmt.Sprintf("failed to fetch encryption key %s", keyID), err, true,
		)
	}

	if tmp := d.db.Delete(&entry); tmp.Error != nil {
		return models.NewSQLError(
			fmt.Sprintf("failed to delete encryption key %s", keyID), tmp.Error, true,
		)
	}

	// Record this event
	if _, err := d.defineNewSystemEvent(
		models.SystemEventTypeDeleteEncryptionKey, models.SystemEventEncKeyRelated{KeyID: keyID},
	); err != nil {
		return goutils.NewRuntimeError(
			"failed to log encryption key state change audit event", err, true,
		)
	}

	return nil
}
