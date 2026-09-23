package db

import (
	"context"
	"fmt"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/models"
	"github.com/google/uuid"
)

/*
RecordEncryptionKey record an encrypted symmetric encryption key

	@param ctx context.Context - execution context
	@param encKeyMaterial string - encrypted key material
	@param kekID string - ID of the primary RSA key pair which encrypted the key material
	@returns the key entry
*/
func (d *databaseImpl) RecordEncryptionKey(
	_ context.Context, encKeyMaterial []byte, kekID string,
) (models.EncryptionKey, error) {
	newEntry := EncryptionKeyDBEntry{
		EncryptionKey: models.EncryptionKey{
			ID:             uuid.NewString(),
			EncKeyMaterial: encKeyMaterial,
			KekID:          kekID,
			State:          models.EncryptionKeyStateActive,
		},
	}

	if err := d.validator.Struct(&newEntry); err != nil {
		return models.EncryptionKey{}, goutils.NewValidationError(
			"new encryption key entry is invalid", err, true,
		)
	}

	if tmp := d.db.Create(&newEntry); tmp.Error != nil {
		return models.EncryptionKey{}, goutils.NewSQLError(
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
	tmp := d.db.Where("id = ?", keyID).First(&entry)
	return entry, notFoundOrError(tmp.Error, "encryption key", keyID)
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
		return nil, goutils.NewSQLError("failed to list encryption keys", tmp.Error, true)
	}

	result := []models.EncryptionKey{}
	for _, entry := range entries {
		result = append(result, entry.EncryptionKey)
	}

	return result, nil
}

/*
UpdateEncryptionKeyWrapping re-wrap an existing encryption key under a different KEK

The key keeps its ID, its state and every record version which references it; only the
wrapped key material and the ID of the key pair which wrapped it change. The symmetric key
itself is untouched, so every cipher text encrypted with it stays valid.

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@param encKeyMaterial []byte - the newly wrapped key material
	@param kekID string - ID of the primary RSA key pair which encrypted the key material
	@returns the updated key entry
*/
func (d *databaseImpl) UpdateEncryptionKeyWrapping(
	_ context.Context, keyID string, encKeyMaterial []byte, kekID string,
) (models.EncryptionKey, error) {
	entry, err := d.getEncryptionKey(keyID)
	if err != nil {
		return models.EncryptionKey{}, err
	}

	entry.EncKeyMaterial = encKeyMaterial
	entry.KekID = kekID

	if err := d.validator.Struct(&entry); err != nil {
		return models.EncryptionKey{}, goutils.NewValidationError(
			fmt.Sprintf("re-wrapped encryption key %s is invalid", keyID), err, true,
		)
	}

	if tmp := d.db.Model(&EncryptionKeyDBEntry{}).
		Where("id = ?", keyID).
		Updates(map[string]interface{}{
			"enc_key_material": encKeyMaterial, "kek_id": kekID,
		}); tmp.Error != nil {
		return models.EncryptionKey{}, goutils.NewSQLError(
			fmt.Sprintf("encryption key %s re-wrap update failed", keyID), tmp.Error, true,
		)
	}

	return entry.EncryptionKey, nil
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
		return goutils.NewSQLError("encryption key state change update failed", tmp.Error, true)
	}

	// Record this event. Retirement is the only transition a key makes, so it is the only
	// event to select.
	if _, err := d.defineNewSystemEvent(
		models.SystemEventTypeRetireEncryptionKey, models.SystemEventEncKeyRelated{KeyID: keyID},
	); err != nil {
		return goutils.NewRuntimeError(
			"failed to log encryption key state change audit event", err, true,
		)
	}

	return nil
}

/*
MarkEncryptionKeyRetired mark encryption key retired, so it only decrypts

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
*/
func (d *databaseImpl) MarkEncryptionKeyRetired(_ context.Context, keyID string) error {
	return d.updateEncKeyState(keyID, models.EncryptionKeyStateRetired)
}

/*
DeleteEncryptionKey delete encryption key

The delete fails while any record version is still encrypted with the key, so a key can
only be removed once its data has been moved onto another one.

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
		return goutils.NewSQLError(
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
