package encryption

import (
	"context"
	"fmt"

	cgoCrypto "github.com/alwitt/cgoutils/crypto"
	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
)

// setupAEAD prepare AEAD
//
// The key buffer is installed as is; the AEAD holds a reference to it for the duration of
// the operation.
func (e *cryptoEngine) setupAEAD(
	ctx context.Context, key cgoCrypto.SecureCSlice, nonce []byte,
) (cgoCrypto.AEAD, error) {
	aead, err := e.crypto.GetAEAD(ctx, cgoCrypto.AEADTypeXChaCha20Poly1305)
	if err != nil {
		return nil, models.NewEncryptionError("unable to define AEAD client", err, true)
	}

	// Set the AEAD encryption key
	if err := aead.SetKey(key); err != nil {
		return nil, models.NewEncryptionError("failed to install AEAD key", err, true)
	}

	// Set the AEAD nonce
	if len(nonce) > 0 {
		// Use existing nonce
		nonceBuffer, err := e.crypto.AllocateSecureCSlice(aead.ExpectedNonceLen())
		if err != nil {
			return nil, models.NewEncryptionError("failed to init AEAD nonce buffer", err, true)
		}
		nonceBufferCore, err := nonceBuffer.GetSlice()
		if err != nil {
			return nil, models.NewEncryptionError("failed to access AEAD nonce buffer core", err, true)
		}
		if copied := copy(nonceBufferCore, nonce); copied != aead.ExpectedNonceLen() {
			return nil, models.NewEncryptionError(
				fmt.Sprintf(
					"failed to fill AEAD nonce buffer core %d =/= %d", copied, aead.ExpectedNonceLen(),
				),
				nil, true,
			)
		}
		if err := aead.SetNonce(nonceBuffer); err != nil {
			return nil, models.NewEncryptionError("failed to install AEAD nonce", err, true)
		}
	} else {
		// Generate random nonce
		nonceBuffer, err := e.crypto.GetRandomBuf(ctx, aead.ExpectedNonceLen())
		if err != nil {
			return nil, models.NewEncryptionError("failed to init AEAD nonce", err, true)
		}
		if err := aead.SetNonce(nonceBuffer); err != nil {
			return nil, models.NewEncryptionError("failed to install AEAD nonce", err, true)
		}
	}

	return aead, nil
}

// normalizeAdditional map an empty associated data slice to nil. The AEAD dereferences the
// first element of any non-nil slice, so an empty non-nil slice must not reach it.
func normalizeAdditional(additional []byte) []byte {
	if len(additional) == 0 {
		return nil
	}
	return additional
}

/*
EncryptData encrypt plain text

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@param plainText []byte - the plain text to encrypt
	@param additional []byte - associated data authenticated with, but not included in,
	    the cipher text. The identical value must be supplied to decrypt. Optional.
	@param activeDBClient Database - existing database transaction
	@return key entry for the encryption, and the cipher text
*/
func (e *cryptoEngine) EncryptData(
	ctx context.Context,
	keyID string,
	plainText []byte,
	additional []byte,
	activeDBClient db.Database,
) (models.EncryptionKey, EncryptedData, error) {
	// The AEAD dereferences the first byte of the plain text
	if len(plainText) == 0 {
		return models.EncryptionKey{}, EncryptedData{}, models.NewEncryptionError(
			"plain text is empty", nil, true,
		)
	}

	keyEntry, err := e.getEncryptionKey(ctx, keyID, activeDBClient)
	if err != nil {
		return models.EncryptionKey{},
			EncryptedData{},
			models.NewEncryptionError(
				fmt.Sprintf("failed to get encryption key %s from cache", keyID), err, true,
			)
	}

	if keyEntry.plainTextKey == nil || !keyEntry.State.CanEncrypt() {
		return models.EncryptionKey{},
			EncryptedData{},
			models.NewEncryptionError(
				fmt.Sprintf("encryption key %s can't encrypt", keyID),
				goutils.NewConsistencyError(
					fmt.Sprintf(
						"encryption key %s is in state '%s', or is not decrypted",
						keyID, keyEntry.State,
					),
					nil, false,
				),
				true,
			)
	}

	aead, err := e.setupAEAD(ctx, keyEntry.plainTextKey, nil)
	if err != nil {
		return models.EncryptionKey{},
			EncryptedData{},
			models.NewEncryptionError("failed to setup AEAD client", err, true)
	}

	// Grab the nonce
	nonce, err := aead.Nonce().GetSlice()
	if err != nil {
		return models.EncryptionKey{},
			EncryptedData{},
			models.NewEncryptionError("failed to get nonce", err, true)
	}
	nonceCopy := make([]byte, aead.ExpectedNonceLen())
	if copied := copy(nonceCopy, nonce); copied != aead.ExpectedNonceLen() {
		return models.EncryptionKey{}, EncryptedData{}, models.NewEncryptionError(
			fmt.Sprintf("failed to copy nonce %d =/= %d", copied, aead.ExpectedNonceLen()), nil, true,
		)
	}

	// Encrypt the plain text
	cipherText := make([]byte, aead.ExpectedCipherLen(int64(len(plainText))))
	if err := aead.Seal(ctx, 0, plainText, normalizeAdditional(additional), cipherText); err != nil {
		return models.EncryptionKey{},
			EncryptedData{},
			models.NewEncryptionError("failed to encrypt plain text", err, true)
	}

	return keyEntry.EncryptionKey, EncryptedData{CipherText: cipherText, Nonce: nonceCopy}, nil
}

/*
DecryptData decrypt cipher text

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@param encrypted EncryptedData - the cipher text to decrypt
	@param additional []byte - the associated data supplied when encrypting
	@param activeDBClient Database - existing database transaction
	@return key entry for the encryption, and the plain text
*/
func (e *cryptoEngine) DecryptData(
	ctx context.Context,
	keyID string,
	encrypted EncryptedData,
	additional []byte,
	activeDBClient db.Database,
) (models.EncryptionKey, []byte, error) {
	keyEntry, err := e.getEncryptionKey(ctx, keyID, activeDBClient)
	if err != nil {
		return models.EncryptionKey{}, nil, models.NewEncryptionError(
			fmt.Sprintf("failed to get encryption key %s from cache", keyID), err, true,
		)
	}

	if keyEntry.plainTextKey == nil || !keyEntry.State.CanDecrypt() {
		return models.EncryptionKey{}, nil, models.NewEncryptionError(
			fmt.Sprintf("encryption key %s can't decrypt", keyID),
			goutils.NewConsistencyError(
				fmt.Sprintf(
					"encryption key %s is in state '%s', or is not decrypted", keyID, keyEntry.State,
				),
				nil, false,
			),
			true,
		)
	}

	aead, err := e.setupAEAD(ctx, keyEntry.plainTextKey, encrypted.Nonce)
	if err != nil {
		return models.EncryptionKey{}, nil, models.NewEncryptionError(
			"failed to setup AEAD client", err, true,
		)
	}

	// A cipher text holding nothing beyond the authentication tag cannot be unsealed: a
	// corrupted row must not reach the AEAD
	plainLen := aead.ExpectedPlainTextLen(int64(len(encrypted.CipherText)))
	if plainLen <= 0 {
		return models.EncryptionKey{}, nil, models.NewEncryptionError(
			fmt.Sprintf("cipher text too short: %d bytes", len(encrypted.CipherText)), nil, true,
		)
	}

	// Decrypt the cipher text
	plainText := make([]byte, plainLen)
	if err := aead.Unseal(
		ctx, 0, encrypted.CipherText, normalizeAdditional(additional), plainText,
	); err != nil {
		return models.EncryptionKey{}, nil, models.NewEncryptionError(
			"failed to decrypt cipher text", err, true,
		)
	}

	return keyEntry.EncryptionKey, plainText, nil
}
