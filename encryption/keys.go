package encryption

import (
	"context"
	"fmt"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
)

/*
NewEncryptionKey define a new encryption symmetric encryption key

	@param ctx context.Context - execution context
	@param activeDBClient Database - existing database transaction
	@returns the key entry
*/
func (e *cryptoEngine) NewEncryptionKey(
	ctx context.Context, activeDBClient db.Database,
) (models.EncryptionKey, error) {
	// RNG for generating the key
	rng := e.crypto.GetRNGReader()

	aead, err := e.crypto.GetAEAD(ctx, crypto.AEADTypeXChaCha20Poly1305)
	if err != nil {
		return models.EncryptionKey{}, fmt.Errorf("unable to define AEAD client [%w]", err)
	}

	keyLen := aead.ExpectedKeyLen()

	newKey := make([]byte, keyLen)
	if n, err := rng.Read(newKey); err != nil {
		return models.EncryptionKey{}, fmt.Errorf("failed to read %d bytes from RNG [%w]", keyLen, err)
	} else if n != keyLen {
		return models.EncryptionKey{}, fmt.Errorf("did not get %d bytes from RNG, only %d", keyLen, n)
	}

	// Encrypt the key for storage
	newKeyEnc, err := e.crypto.RSAEncrypt(ctx, newKey, e.rsaPubKey, nil)
	if err != nil {
		return models.EncryptionKey{}, fmt.Errorf("failed to encrypt symmetric enc key [%w]", err)
	}

	// Record the key
	var keyEntry models.EncryptionKey
	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			keyEntry, err = dbClient.RecordEncryptionKey(dbCtx, newKeyEnc)
			return err
		},
	); dbErr != nil {
		return models.EncryptionKey{}, fmt.Errorf("failed to record new encryption key [%w]", dbErr)
	}

	// Cache the key and its DB entry
	e.writeKeyToCache(keyEntry, newKey)

	return keyEntry, nil
}

// writeKeyToCache write key into cache for use
func (e *cryptoEngine) writeKeyToCache(keyEntry models.EncryptionKey, plainKey []byte) {
	e.keyCacheLock.Lock()
	defer e.keyCacheLock.Unlock()
	e.encKeys[keyEntry.ID] = encKeyCacheEntry{EncryptionKey: keyEntry, plainTextKey: plainKey}
}

// getCachedKey helper function to read a key from cache
func (e *cryptoEngine) getCachedKey(keyID string) (encKeyCacheEntry, bool) {
	e.keyCacheLock.RLock()
	defer e.keyCacheLock.RUnlock()
	entry, ok := e.encKeys[keyID]
	return entry, ok
}

func (e *cryptoEngine) cacheKey(
	ctx context.Context, keyEntry models.EncryptionKey,
) (encKeyCacheEntry, error) {
	// Only cache active keys
	if keyEntry.State != models.EncryptionKeyStateActive {
		return encKeyCacheEntry{EncryptionKey: keyEntry}, nil
	}

	// Decrypt the key
	key, err := e.crypto.RSADecrypt(ctx, keyEntry.EncKeyMaterial, e.rsaKey, nil)
	if err != nil {
		return encKeyCacheEntry{EncryptionKey: keyEntry}, fmt.Errorf(
			"failed to decrypt symmetric key %s [%w]", keyEntry.ID, err,
		)
	}

	// Cache the key and its DB entry
	e.writeKeyToCache(keyEntry, key)

	return encKeyCacheEntry{EncryptionKey: keyEntry, plainTextKey: key}, nil
}

// uncacheKey remove a key from cache
func (e *cryptoEngine) uncacheKey(keyID string) {
	// Delete the key from cache
	e.keyCacheLock.Lock()
	defer e.keyCacheLock.Unlock()
	delete(e.encKeys, keyID)
}

// getEncryptionKey core function for fetching on encryption key
func (e *cryptoEngine) getEncryptionKey(
	ctx context.Context, keyID string, activeDBClient db.Database,
) (encKeyCacheEntry, error) {
	var keyEntry models.EncryptionKey
	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			var err error
			keyEntry, err = dbClient.GetEncryptionKey(dbCtx, keyID)
			return err
		},
	); dbErr != nil {
		return encKeyCacheEntry{}, fmt.Errorf("encryption key %s unknown [%w]", keyID, dbErr)
	}

	// Inactive keys are not cached
	if keyEntry.State != models.EncryptionKeyStateActive {
		return encKeyCacheEntry{EncryptionKey: keyEntry}, nil
	}

	var plainKey encKeyCacheEntry
	cached := false
	var err error

	// Check key has been cached already
	if plainKey, cached = e.getCachedKey(keyID); !cached {
		if plainKey, err = e.cacheKey(ctx, keyEntry); err != nil {
			return encKeyCacheEntry{}, fmt.Errorf(
				"unable to cache encryption key %s [%w]", keyID, err,
			)
		}
	}
	return plainKey, nil
}

/*
GetEncryptionKey fetch one encryption key

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@param activeDBClient Database - existing database transaction
	@return key entry
*/
func (e *cryptoEngine) GetEncryptionKey(
	ctx context.Context, keyID string, activeDBClient db.Database,
) (models.EncryptionKey, error) {
	keyEntry, err := e.getEncryptionKey(ctx, keyID, activeDBClient)
	return keyEntry.EncryptionKey, err
}

/*
ListEncryptionKeys list encryption keys

	@param ctx context.Context - execution context
	@param filters EncryptionKeyQueryFilter - entry listing filter
	@param activeDBClient Database - existing database transaction
	@return list of keys
*/
func (e *cryptoEngine) ListEncryptionKeys(
	ctx context.Context, filters db.EncryptionKeyQueryFilter, activeDBClient db.Database,
) ([]models.EncryptionKey, error) {
	var keyEntries []models.EncryptionKey
	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			var err error
			keyEntries, err = dbClient.ListEncryptionKeys(dbCtx, filters)
			return err
		},
	); dbErr != nil {
		return nil, fmt.Errorf("failed to list encryption keys [%w]", dbErr)
	}

	// Check keys have been cached already
	for _, entry := range keyEntries {
		if entry.State == models.EncryptionKeyStateActive {
			if _, cached := e.getCachedKey(entry.ID); !cached {
				if _, err := e.cacheKey(ctx, entry); err != nil {
					return nil, fmt.Errorf(
						"unable to cache encryption key %s [%w]", entry.ID, err,
					)
				}
			}
		} else {
			e.uncacheKey(entry.ID)
		}
	}

	return keyEntries, nil
}

/*
MarkEncryptionKeyActive mark encryption key is active

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@param activeDBClient Database - existing database transaction
	@return key entry
*/
func (e *cryptoEngine) MarkEncryptionKeyActive(
	ctx context.Context, keyID string, activeDBClient db.Database,
) (models.EncryptionKey, error) {
	var keyEntry models.EncryptionKey
	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			var err error
			if err = dbClient.MarkEncryptionKeyActive(dbCtx, keyID); err != nil {
				return fmt.Errorf("failed to mark encryptio key %s active [%w]", keyID, err)
			}
			keyEntry, err = dbClient.GetEncryptionKey(dbCtx, keyID)
			if err != nil {
				return fmt.Errorf("failed to fetch encryption key %s [%w]", keyID, err)
			}
			// Update the entry in cache
			if _, err := e.cacheKey(ctx, keyEntry); err != nil {
				return fmt.Errorf(
					"unable to cache encryption key %s [%w]", keyEntry.ID, err,
				)
			}
			return nil
		},
	); dbErr != nil {
		return models.EncryptionKey{}, fmt.Errorf(
			"failed to activate encryption key %s [%w]", keyID, dbErr,
		)
	}

	return keyEntry, nil
}

/*
MarkEncryptionKeyInactive mark encryption key is inactive

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@param activeDBClient Database - existing database transaction
	@return key entry
*/
func (e *cryptoEngine) MarkEncryptionKeyInactive(
	ctx context.Context, keyID string, activeDBClient db.Database,
) (models.EncryptionKey, error) {
	var keyEntry models.EncryptionKey
	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			var err error
			if err = dbClient.MarkEncryptionKeyInactive(dbCtx, keyID); err != nil {
				return fmt.Errorf("failed to mark encryptio key %s inactive [%w]", keyID, err)
			}
			keyEntry, err = dbClient.GetEncryptionKey(dbCtx, keyID)
			if err != nil {
				return fmt.Errorf("failed to fetch encryption key %s [%w]", keyID, err)
			}
			return nil
		},
	); dbErr != nil {
		return models.EncryptionKey{}, fmt.Errorf(
			"failed to deactivate encryption key %s [%w]", keyID, dbErr,
		)
	}

	// Delete the key from cache
	e.uncacheKey(keyEntry.ID)

	return keyEntry, nil
}

/*
DeleteEncryptionKey delete encryption key

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@param activeDBClient Database - existing database transaction
*/
func (e *cryptoEngine) DeleteEncryptionKey(
	ctx context.Context, keyID string, activeDBClient db.Database,
) error {
	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			return dbClient.DeleteEncryptionKey(dbCtx, keyID)
		},
	); dbErr != nil {
		return fmt.Errorf("failed to delete encryption key %s [%w]", keyID, dbErr)
	}

	// Delete the key from cache
	e.keyCacheLock.Lock()
	defer e.keyCacheLock.Unlock()
	delete(e.encKeys, keyID)

	return nil
}
