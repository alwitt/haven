package encryption

import (
	"context"
	"fmt"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
)

/*
UndecryptableVersion a record version whose cipher text will not unseal

A decryption failure under the key the row names is evidence of corruption or tampering:
the associated data exists to detect the latter. It is both the halt condition of
ReEncryptRecordVersions and the element type of FindUndecryptableVersions, because the two
report the same finding in different shapes.
*/
type UndecryptableVersion struct {
	// Version the record version as it was read
	Version models.RecordVersion
	// Cause the underlying authentication failure
	Cause error
}

// Error the error string
func (u UndecryptableVersion) Error() string {
	return fmt.Sprintf(
		"record version '%s' of record '%s' will not decrypt with encryption key '%s'",
		u.Version.ID, u.Version.RecordID, u.Version.EncKeyID,
	)
}

// Unwrap the underlying authentication failure
func (u UndecryptableVersion) Unwrap() error {
	return u.Cause
}

/*
ReEncryptRecordVersions move record versions onto a different encryption key

	@param ctx context.Context - execution context
	@param versions []models.RecordVersion - the versions to move
	@param targetKey models.EncryptionKey - the key to move them onto
	@param activeDBClient Database - existing database transaction
*/
func (e *cryptoEngine) ReEncryptRecordVersions(
	ctx context.Context,
	versions []models.RecordVersion,
	targetKey models.EncryptionKey,
	activeDBClient db.Database,
) error {
	return db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			for _, version := range versions {
				// The version already sits on the target key. A page which overlaps work already
				// done is converted again without effect.
				if version.EncKeyID == targetKey.ID {
					continue
				}

				if err := e.reEncryptOneVersion(dbCtx, version, targetKey, dbClient); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

// reEncryptOneVersion move one record version onto a different encryption key
//
// The version is decrypted with the associated data as the row currently stands, and
// re-sealed with the associated data recomputed from the new encryption key ID. Changing
// the key changes the associated data, so the two are never the same value.
func (e *cryptoEngine) reEncryptOneVersion(
	ctx context.Context,
	version models.RecordVersion,
	targetKey models.EncryptionKey,
	dbClient db.Database,
) error {
	_, plainText, err := e.DecryptData(
		ctx,
		version.EncKeyID,
		EncryptedData{CipherText: version.EncValue, Nonce: version.EncNonce},
		version.AssociatedData(),
		dbClient,
	)
	if err != nil {
		return UndecryptableVersion{Version: version, Cause: err}
	}
	defer clear(plainText)

	// The associated data of the row as it will stand once the key changes
	reKeyed := version
	reKeyed.EncKeyID = targetKey.ID

	_, encrypted, err := e.EncryptData(
		ctx, targetKey.ID, plainText, reKeyed.AssociatedData(), dbClient,
	)
	if err != nil {
		return models.NewEncryptionError(
			fmt.Sprintf(
				"failed to re-encrypt record version %s with encryption key %s",
				version.ID, targetKey.ID,
			),
			err, true,
		)
	}

	if _, err := dbClient.UpdateRecordVersionEncryption(
		ctx, version.ID, targetKey, encrypted.CipherText, encrypted.Nonce,
	); err != nil {
		return goutils.NewPersistenceError(
			fmt.Sprintf("failed to record re-encrypted record version %s", version.ID), err, true,
		)
	}

	return nil
}

/*
FindUndecryptableVersions report which record versions will not decrypt

	@param ctx context.Context - execution context
	@param versions []models.RecordVersion - the versions to check
	@param activeDBClient Database - existing database transaction
	@returns one finding per version which failed to decrypt
*/
func (e *cryptoEngine) FindUndecryptableVersions(
	ctx context.Context,
	versions []models.RecordVersion,
	activeDBClient db.Database,
) ([]UndecryptableVersion, error) {
	findings := []UndecryptableVersion{}

	if dbErr := db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			for _, version := range versions {
				_, plainText, err := e.DecryptData(
					dbCtx,
					version.EncKeyID,
					EncryptedData{CipherText: version.EncValue, Nonce: version.EncNonce},
					version.AssociatedData(),
					dbClient,
				)
				if err != nil {
					findings = append(findings, UndecryptableVersion{Version: version, Cause: err})
					continue
				}
				clear(plainText)
			}
			return nil
		},
	); dbErr != nil {
		return nil, models.NewEncryptionError(
			"failed to check record versions for decryption failures", dbErr, true,
		)
	}

	return findings, nil
}

/*
RewrapEncryptionKeys re-wrap encryption keys under a different primary RSA key pair

	@param ctx context.Context - execution context
	@param keys []models.EncryptionKey - the keys to re-wrap
	@param newKEK KEK - the key pair to re-wrap them under
	@param activeDBClient Database - existing database transaction
*/
func (e *cryptoEngine) RewrapEncryptionKeys(
	ctx context.Context,
	keys []models.EncryptionKey,
	newKEK KEK,
	activeDBClient db.Database,
) error {
	if newKEK.ID() == e.kek.ID() {
		return models.NewEncryptionError(
			fmt.Sprintf(
				"primary RSA key pair '%s' is the one already in use; it is not a rotation target",
				newKEK.ID(),
			),
			nil, true,
		)
	}

	return db.ActiveSessionWrapper(
		ctx, activeDBClient, e.persistence, func(dbCtx context.Context, dbClient db.Database) error {
			for _, key := range keys {
				// Already re-wrapped by an earlier run. This is checked before anything reads the
				// key material, as unwrapping it with the key pair in use would fail.
				if key.KekID == newKEK.ID() {
					continue
				}

				if key.KekID != e.kek.ID() {
					return models.NewEncryptionError(
						fmt.Sprintf(
							"encryption key %s is wrapped by primary RSA key pair '%s', "+
								"which is neither the one in use '%s' nor the new one '%s'",
							key.ID, key.KekID, e.kek.ID(), newKEK.ID(),
						),
						nil, true,
					)
				}

				if err := e.rewrapOneKey(dbCtx, key, newKEK, dbClient); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

// rewrapOneKey re-wrap one encryption key under a different primary RSA key pair
//
// The symmetric key is read through the cache, so a key already in use is not unwrapped a
// second time.
func (e *cryptoEngine) rewrapOneKey(
	ctx context.Context, key models.EncryptionKey, newKEK KEK, dbClient db.Database,
) error {
	cached, err := e.getEncryptionKey(ctx, key.ID, dbClient)
	if err != nil {
		return models.NewEncryptionError(
			fmt.Sprintf("failed to unwrap encryption key %s", key.ID), err, true,
		)
	}
	if cached.plainTextKey == nil {
		return models.NewEncryptionError(
			fmt.Sprintf("encryption key %s is not decrypted", key.ID), nil, true,
		)
	}

	plainKey, err := cached.plainTextKey.GetSlice()
	if err != nil {
		return models.NewEncryptionError(
			fmt.Sprintf("failed to access the key buffer core of encryption key %s", key.ID),
			err, true,
		)
	}

	newKeyEnc, err := e.crypto.RSAEncrypt(ctx, plainKey, newKEK.publicKey, nil)
	if err != nil {
		return models.NewEncryptionError(
			fmt.Sprintf("failed to re-wrap encryption key %s", key.ID), err, true,
		)
	}

	updated, err := dbClient.UpdateEncryptionKeyWrapping(ctx, key.ID, newKeyEnc, newKEK.ID())
	if err != nil {
		return goutils.NewPersistenceError(
			fmt.Sprintf("failed to record re-wrapped encryption key %s", key.ID), err, true,
		)
	}

	// Refresh the cache against the new row. Routing this through cacheKey would try to
	// unwrap the new key material with the key pair in use, which by definition can't.
	e.writeKeyToCache(updated, cached.plainTextKey)

	return nil
}
