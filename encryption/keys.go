package encryption

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/alwitt/goutils"
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
	aead, err := e.crypto.GetAEAD(ctx, crypto.AEADTypeXChaCha20Poly1305)
	if err != nil {
		return models.EncryptionKey{}, models.NewEncryptionError("unable to define AEAD client", err, true)
	}

	keyLen := aead.ExpectedKeyLen()

	// Draw the key directly into secure memory
	newKey, err := e.crypto.GetRandomBuf(ctx, keyLen)
	if err != nil {
		return models.EncryptionKey{}, models.NewEncryptionError(
			fmt.Sprintf("failed to generate %d byte key", keyLen), err, true,
		)
	}
	newKeyView, err := newKey.GetSlice()
	if err != nil {
		return models.EncryptionKey{}, models.NewEncryptionError(
			"failed to access new key buffer core", err, true,
		)
	}

	// Encrypt the key for storage
	newKeyEnc, err := e.crypto.RSAEncrypt(ctx, newKeyView, e.kek.publicKey, nil)
	if err != nil {
		return models.EncryptionKey{}, models.NewEncryptionError(
			"failed to encrypt symmetric enc key", err, true,
		)
	}

	// Record the key
	var keyEntry models.EncryptionKey
	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			keyEntry, err = dbClient.RecordEncryptionKey(dbCtx, newKeyEnc, e.kek.ID())
			if err != nil {
				return goutils.NewPersistenceError("failed to record encryption key", err, true)
			}
			return nil
		},
	); dbErr != nil {
		return models.EncryptionKey{}, models.NewEncryptionError(
			"failed to record new encryption key", dbErr, true,
		)
	}

	// Cache the key and its DB entry
	e.writeKeyToCache(keyEntry, newKey)

	return keyEntry, nil
}

// writeKeyToCache write key into cache for use, trusted for the configured TTL
func (e *cryptoEngine) writeKeyToCache(
	keyEntry models.EncryptionKey, plainKey crypto.SecureCSlice,
) encKeyCacheEntry {
	entry := encKeyCacheEntry{
		EncryptionKey: keyEntry,
		plainTextKey:  plainKey,
		expiresAt:     time.Now().UTC().Add(e.keyCacheTTL),
	}
	e.keyCacheLock.Lock()
	defer e.keyCacheLock.Unlock()
	e.encKeys[keyEntry.ID] = entry
	return entry
}

// getCachedKey helper function to read a key from cache
func (e *cryptoEngine) getCachedKey(keyID string) (encKeyCacheEntry, bool) {
	e.keyCacheLock.RLock()
	defer e.keyCacheLock.RUnlock()
	entry, ok := e.encKeys[keyID]
	return entry, ok
}

// cacheKey record an encryption key entry in the cache. A key which can still decrypt is
// cached; one which cannot evicts any existing entry.
//
// Retired keys are cached deliberately: an encryption key rotation decrypts under the
// retired key for every version it moves, so evicting it would cost an RSA unwrap per row.
//
// If the key is already cached and its wrapped key material is unchanged, the decrypted
// key is reused and only the metadata and TTL are refreshed.
func (e *cryptoEngine) cacheKey(
	ctx context.Context, keyEntry models.EncryptionKey,
) (encKeyCacheEntry, error) {
	if !keyEntry.State.CanDecrypt() {
		e.uncacheKey(keyEntry.ID)
		return encKeyCacheEntry{EncryptionKey: keyEntry}, nil
	}

	// Reuse the already decrypted key when possible
	{
		existing, ok := e.getCachedKey(keyEntry.ID)
		if ok &&
			existing.plainTextKey != nil &&
			bytes.Equal(existing.EncKeyMaterial, keyEntry.EncKeyMaterial) {
			return e.writeKeyToCache(keyEntry, existing.plainTextKey), nil
		}
	}

	// Decrypt the key, and move it into secure memory
	rawKey, err := e.crypto.RSADecrypt(ctx, keyEntry.EncKeyMaterial, e.kek.privateKey, nil)
	if err != nil {
		return encKeyCacheEntry{EncryptionKey: keyEntry}, models.NewEncryptionError(
			fmt.Sprintf("failed to decrypt symmetric key %s", keyEntry.ID), err, true,
		)
	}
	defer clear(rawKey)

	key, err := e.crypto.AllocateSecureCSlice(len(rawKey))
	if err != nil {
		return encKeyCacheEntry{EncryptionKey: keyEntry}, models.NewEncryptionError(
			fmt.Sprintf("failed to allocate secure buffer for key %s", keyEntry.ID), err, true,
		)
	}
	keyCore, err := key.GetSlice()
	if err != nil {
		return encKeyCacheEntry{EncryptionKey: keyEntry}, models.NewEncryptionError(
			fmt.Sprintf("failed to access secure buffer core for key %s", keyEntry.ID), err, true,
		)
	}
	if copied := copy(keyCore, rawKey); copied != len(rawKey) {
		return encKeyCacheEntry{EncryptionKey: keyEntry}, models.NewEncryptionError(
			fmt.Sprintf(
				"failed to fill secure buffer for key %s %d =/= %d", keyEntry.ID, copied, len(rawKey),
			),
			nil, true,
		)
	}

	return e.writeKeyToCache(keyEntry, key), nil
}

// uncacheKey remove a key from cache
//
// The secure buffer is not zeroed here: an in-flight AEAD operation may still hold a
// reference to it. libsodium zeroes and frees the buffer once the last reference is gone.
func (e *cryptoEngine) uncacheKey(keyID string) {
	e.keyCacheLock.Lock()
	defer e.keyCacheLock.Unlock()
	delete(e.encKeys, keyID)
}

// getEncryptionKey core function for fetching on encryption key
//
// A cached entry within its TTL is returned as is. Otherwise the key is re-read from
// persistence and the cache refreshed.
func (e *cryptoEngine) getEncryptionKey(
	ctx context.Context, keyID string, activeDBClient db.Database,
) (encKeyCacheEntry, error) {
	if cached, ok := e.getCachedKey(keyID); ok && time.Now().UTC().Before(cached.expiresAt) {
		return cached, nil
	}

	var keyEntry models.EncryptionKey
	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			var err error
			keyEntry, err = dbClient.GetEncryptionKey(dbCtx, keyID)
			if err != nil {
				return goutils.NewPersistenceError(
					fmt.Sprintf("failed to fetch encryption key %s", keyID), err, true,
				)
			}
			return nil
		},
	); dbErr != nil {
		return encKeyCacheEntry{}, models.NewEncryptionError(
			fmt.Sprintf("encryption key %s unknown", keyID), dbErr, true,
		)
	}

	entry, err := e.cacheKey(ctx, keyEntry)
	if err != nil {
		return encKeyCacheEntry{}, models.NewEncryptionError(
			fmt.Sprintf("unable to cache encryption key %s", keyID), err, true,
		)
	}
	return entry, nil
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
			if err != nil {
				return goutils.NewPersistenceError("failed to list encryption keys", err, true)
			}
			return nil
		},
	); dbErr != nil {
		return nil, models.NewEncryptionError("failed to list encryption keys", dbErr, true)
	}

	// Refresh the cache with the listed keys
	for _, entry := range keyEntries {
		if _, err := e.cacheKey(ctx, entry); err != nil {
			return nil, models.NewEncryptionError(
				fmt.Sprintf("unable to cache encryption key %s", entry.ID), err, true,
			)
		}
	}

	return keyEntries, nil
}
