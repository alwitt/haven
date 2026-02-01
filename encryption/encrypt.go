package encryption

import (
	"context"
	"fmt"

	cgoCrypto "github.com/alwitt/cgoutils/crypto"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
)

// setupAEAD prepare AEAD
func (e *cryptoEngine) setupAEAD(
	ctx context.Context, key []byte, nonce []byte,
) (cgoCrypto.AEAD, error) {
	aead, err := e.crypto.GetAEAD(ctx, cgoCrypto.AEADTypeXChaCha20Poly1305)
	if err != nil {
		return nil, fmt.Errorf("unable to define AEAD client [%w]", err)
	}

	// Set the AEAD encryption key
	keyBuffer, err := e.crypto.AllocateSecureCSlice(aead.ExpectedKeyLen())
	if err != nil {
		return nil, fmt.Errorf("failed to init AEAD key buffer [%w]", err)
	}
	keyBufferCore, err := keyBuffer.GetSlice()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to access AEAD key buffer core [%w]", err,
		)
	}
	if copied := copy(keyBufferCore, key); copied != aead.ExpectedKeyLen() {
		return nil, fmt.Errorf(
			"failed to fill AEAD key buffer core %d =/= %d", copied, aead.ExpectedKeyLen(),
		)
	}
	if err := aead.SetKey(keyBuffer); err != nil {
		return nil, fmt.Errorf("failed to install AEAD key [%w]", err)
	}

	// Set the AEAD nonce
	if len(nonce) > 0 {
		// Use existing nonce
		nonceBuffer, err := e.crypto.AllocateSecureCSlice(aead.ExpectedNonceLen())
		if err != nil {
			return nil, fmt.Errorf("failed to init AEAD nonce buffer [%w]", err)
		}
		nonceBufferCore, err := nonceBuffer.GetSlice()
		if err != nil {
			return nil, fmt.Errorf(
				"failed to access AEAD nonce buffer core [%w]", err,
			)
		}
		if copied := copy(nonceBufferCore, nonce); copied != aead.ExpectedNonceLen() {
			return nil, fmt.Errorf(
				"failed to fill AEAD nonce buffer core %d =/= %d", copied, aead.ExpectedNonceLen(),
			)
		}
		if err := aead.SetNonce(nonceBuffer); err != nil {
			return nil, fmt.Errorf("failed to install AEAD nonce [%w]", err)
		}
	} else {
		// Generate random nonce
		nonceBuffer, err := e.crypto.GetRandomBuf(ctx, aead.ExpectedNonceLen())
		if err != nil {
			return nil, fmt.Errorf("failed to init AEAD nonce [%w]", err)
		}
		if err := aead.SetNonce(nonceBuffer); err != nil {
			return nil, fmt.Errorf("failed to install AEAD nonce [%w]", err)
		}
	}

	return aead, nil
}

/*
EncryptData encrypt plain text

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@param plainText []byte - the plain text to encrypt
	@param activeDBClient Database - existing database transaction
	@return key entry for the encryption, and the cipher text
*/
func (e *cryptoEngine) EncryptData(
	ctx context.Context, keyID string, plainText []byte, activeDBClient db.Database,
) (models.EncryptionKey, EncryptedData, error) {
	keyEntry, err := e.getEncryptionKey(ctx, keyID, activeDBClient)
	if err != nil {
		return models.EncryptionKey{},
			EncryptedData{},
			fmt.Errorf("failed to get encryption key %s from cached [%w]", keyID, err)
	}

	if len(keyEntry.plainTextKey) == 0 || keyEntry.State != models.EncryptionKeyStateActive {
		return models.EncryptionKey{},
			EncryptedData{},
			fmt.Errorf("failed to encryption key %s is not active or not decrypted [%w]", keyID, err)
	}

	aead, err := e.setupAEAD(ctx, keyEntry.plainTextKey, nil)
	if err != nil {
		return models.EncryptionKey{},
			EncryptedData{},
			fmt.Errorf("failed to setup AEAD client [%w]", err)
	}

	// Grab the nonce
	nonce, err := aead.Nonce().GetSlice()
	if err != nil {
		return models.EncryptionKey{}, EncryptedData{}, fmt.Errorf("failed to get nonce [%w]", err)
	}
	nonceCopy := make([]byte, aead.ExpectedNonceLen())
	if copied := copy(nonceCopy, nonce); copied != aead.ExpectedNonceLen() {
		return models.EncryptionKey{}, EncryptedData{}, fmt.Errorf(
			"failed to copy nonce %d =/= %d", copied, aead.ExpectedNonceLen(),
		)
	}

	// Encrypt the plain text
	cipherText := make([]byte, aead.ExpectedCipherLen(int64(len(plainText))))
	if err := aead.Seal(ctx, 0, plainText, nil, cipherText); err != nil {
		return models.EncryptionKey{},
			EncryptedData{},
			fmt.Errorf("failed to encrypt plain text [%w]", err)
	}

	return keyEntry.EncryptionKey, EncryptedData{CipherText: cipherText, Nonce: nonceCopy}, nil
}

/*
DecryptData decrypt cipher text

	@param ctx context.Context - execution context
	@param keyID string - the encryption key ID
	@param encrypted EncryptedData - the cipher text to decrypt
	@param activeDBClient Database - existing database transaction
	@return key entry for the encryption, and the cipher text
*/
func (e *cryptoEngine) DecryptData(
	ctx context.Context, keyID string, encrypted EncryptedData, activeDBClient db.Database,
) (models.EncryptionKey, []byte, error) {
	keyEntry, err := e.getEncryptionKey(ctx, keyID, activeDBClient)
	if err != nil {
		return models.EncryptionKey{}, nil, fmt.Errorf(
			"failed to get encryption key %s from cached [%w]", keyID, err,
		)
	}

	if len(keyEntry.plainTextKey) == 0 || keyEntry.State != models.EncryptionKeyStateActive {
		return models.EncryptionKey{}, nil, fmt.Errorf(
			"failed to encryption key %s is not active or not decrypted [%w]", keyID, err,
		)
	}

	aead, err := e.setupAEAD(ctx, keyEntry.plainTextKey, encrypted.Nonce)
	if err != nil {
		return models.EncryptionKey{}, nil, fmt.Errorf("failed to setup AEAD client [%w]", err)
	}

	// Decrypt the cipher text
	plainText := make([]byte, aead.ExpectedPlainTextLen(int64(len(encrypted.CipherText))))
	if err := aead.Unseal(ctx, 0, encrypted.CipherText, nil, plainText); err != nil {
		return models.EncryptionKey{}, nil, fmt.Errorf("failed to decrypt cipher text [%w]", err)
	}

	return keyEntry.EncryptionKey, plainText, nil
}
