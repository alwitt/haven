package encryption

import (
	"context"
	"errors"
	"testing"

	cgoCrypto "github.com/alwitt/cgoutils/crypto"
	mockcrypto "github.com/alwitt/cgoutils/mocks/crypto"
	mockdb "github.com/alwitt/haven/mocks/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestCryptoEngineRewrapOneKeyFaults verifies that a key is never recorded under the new
// primary RSA key pair when any step of re-wrapping it fails.
//
// A key whose row says it is wrapped by the new pair but whose material is not would be
// unreadable forever, so every failure here has to stop before the write.
func TestCryptoEngineRewrapOneKeyFaults(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	injected := errors.New("cgoutils failure")

	tests := []struct {
		name string
		// seed place the key in the cache as the failing case requires
		seed func(*testing.T, *cryptoEngine, models.EncryptionKey)
		// wire a failure in the cryptography engine itself
		wire    func(*mockcrypto.Engine)
		expects string
	}{
		{
			name: "cached key is not decrypted",
			seed: func(_ *testing.T, uut *cryptoEngine, key models.EncryptionKey) {
				uut.writeKeyToCache(key, nil)
			},
			expects: "is not decrypted",
		},
		{
			name: "key buffer is unreadable",
			seed: func(t *testing.T, uut *cryptoEngine, key models.EncryptionKey) {
				uut.writeKeyToCache(key, newHealthySecureCSlice(
					t, testAEADKeyLen, func(buffer *mockcrypto.SecureCSlice) {
						buffer.On("GetSlice").Return(nil, injected).Once()
					},
				))
			},
			expects: "failed to access the key buffer core of encryption key",
		},
		{
			name: "re-wrap fails",
			seed: func(t *testing.T, uut *cryptoEngine, key models.EncryptionKey) {
				uut.writeKeyToCache(key, newHealthySecureCSlice(t, testAEADKeyLen))
			},
			wire: func(mockCrypto *mockcrypto.Engine) {
				mockCrypto.On(
					"RSAEncrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
				).Return(nil, injected).Once()
			},
			expects: "failed to re-wrap encryption key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)

			uut, mockCrypto := newMockedCryptoEngine(t)
			if test.wire != nil {
				test.wire(mockCrypto)
			}
			expectHealthyCryptoCalls(t, mockCrypto, newHealthyAEAD(t))

			// Wrapped by the pair in use, so it is neither skipped nor rejected as a stray
			keyEntry := testCacheableKey(uut.kek.ID())
			test.seed(t, uut, keyEntry)

			newKEK := testKEK(t, "user-root.crt", "user-root.key")
			assert.NotEqual(uut.kek.ID(), newKEK.ID())

			// The database mock carries no expectations: reaching the write is itself a failure
			err := uut.RewrapEncryptionKeys(
				utCtx, []models.EncryptionKey{keyEntry}, newKEK, mockdb.NewDatabase(t),
			)
			assert.Error(err)
			assert.ErrorContains(err, test.expects)

			var encryptionErr models.EncryptionError
			assert.True(errors.As(err, &encryptionErr))
		})
	}
}

// TestCryptoEngineRewrapOneKeyRefreshesCache verifies that a re-wrapped key is cached
// against its new row while keeping the decrypted key it already held.
//
// Routing the refresh through cacheKey would try to unwrap the new material with the key
// pair in use, which by definition cannot work — so the decrypted buffer has to carry over
// untouched.
func TestCryptoEngineRewrapOneKeyRefreshesCache(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	uut, mockCrypto := newMockedCryptoEngine(t)
	expectHealthyCryptoCalls(t, mockCrypto, newHealthyAEAD(t))

	keyEntry := testCacheableKey(uut.kek.ID())
	plainKey := newHealthySecureCSlice(t, testAEADKeyLen)
	uut.writeKeyToCache(keyEntry, plainKey)

	newKEK := testKEK(t, "user-root.crt", "user-root.key")

	rewrapped := keyEntry
	rewrapped.EncKeyMaterial = []byte("wrapped-under-the-new-pair")
	rewrapped.KekID = newKEK.ID()

	mockDatabase := mockdb.NewDatabase(t)
	mockDatabase.On(
		"UpdateEncryptionKeyWrapping",
		mock.Anything,
		keyEntry.ID,
		mock.AnythingOfType("[]uint8"),
		newKEK.ID(),
	).Return(rewrapped, nil).Once()

	assert.Nil(uut.RewrapEncryptionKeys(
		utCtx, []models.EncryptionKey{keyEntry}, newKEK, mockDatabase,
	))

	// The cache now describes the new row, still holding the key it already had decrypted
	cached, present := uut.getCachedKey(keyEntry.ID)
	assert.True(present)
	assert.Equal(newKEK.ID(), cached.KekID)
	assert.Equal(rewrapped.EncKeyMaterial, cached.EncKeyMaterial)
	assert.True(cached.plainTextKey == cgoCrypto.SecureCSlice(plainKey))
}
