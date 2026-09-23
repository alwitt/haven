package encryption

import (
	"context"
	"errors"
	"testing"

	mockcrypto "github.com/alwitt/cgoutils/mocks/crypto"
	mockdb "github.com/alwitt/haven/mocks/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// testCacheableKey a key entry cacheKey will accept
func testCacheableKey(kekID string) models.EncryptionKey {
	return models.EncryptionKey{
		ID:             uuid.NewString(),
		State:          models.EncryptionKeyStateActive,
		EncKeyMaterial: []byte("wrapped-key-material"),
		KekID:          kekID,
	}
}

// TestCryptoEngineCacheKeyEvictsNonDecryptable verifies that a key which may not decrypt is
// dropped from the cache rather than left in it.
//
// Both live states decrypt, so nothing in the public API reaches this branch. It is the
// engine's protection against holding a decrypted key it has been told it may no longer use,
// and only a white-box test can show it does the eviction rather than merely skipping.
func TestCryptoEngineCacheKeyEvictsNonDecryptable(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut, mockCrypto := newMockedCryptoEngine(t)
	expectHealthyCryptoCalls(t, mockCrypto, newHealthyAEAD(t))

	keyEntry := testCacheableKey(uut.kek.ID())

	// Cached while it can still decrypt
	cached, err := uut.cacheKey(utCtx, keyEntry)
	assert.Nil(err)
	assert.NotNil(cached.plainTextKey)
	_, present := uut.getCachedKey(keyEntry.ID)
	assert.True(present)

	// The same key, now in a state which permits neither operation
	keyEntry.State = models.EncryptionKeyStateENUMType("DESTROYED")
	evicted, err := uut.cacheKey(utCtx, keyEntry)
	assert.Nil(err)
	assert.Nil(evicted.plainTextKey)
	assert.Equal(keyEntry.State, evicted.State)

	_, present = uut.getCachedKey(keyEntry.ID)
	assert.False(present)
}

// TestCryptoEngineCacheKeyReusesDecryptedKey verifies that re-caching a key whose wrapped
// material is unchanged reuses the decrypted key, and that re-wrapped material does not.
//
// The reuse is what keeps a KEK rotation from unwrapping the same key once per refresh; the
// re-unwrap is what keeps a re-wrapped key from being read through a stale buffer.
func TestCryptoEngineCacheKeyReusesDecryptedKey(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	uut, mockCrypto := newMockedCryptoEngine(t)
	expectHealthyCryptoCalls(t, mockCrypto, newHealthyAEAD(t))

	keyEntry := testCacheableKey(uut.kek.ID())

	first, err := uut.cacheKey(utCtx, keyEntry)
	assert.Nil(err)
	mockCrypto.AssertNumberOfCalls(t, "RSADecrypt", 1)

	// Unchanged material: the decrypted key is reused, and only the TTL moves
	second, err := uut.cacheKey(utCtx, keyEntry)
	assert.Nil(err)
	mockCrypto.AssertNumberOfCalls(t, "RSADecrypt", 1)
	assert.True(first.plainTextKey == second.plainTextKey)
	assert.False(second.expiresAt.Before(first.expiresAt))

	// Re-wrapped material: the key is unwrapped again
	keyEntry.EncKeyMaterial = []byte("re-wrapped-key-material")
	third, err := uut.cacheKey(utCtx, keyEntry)
	assert.Nil(err)
	mockCrypto.AssertNumberOfCalls(t, "RSADecrypt", 2)
	assert.False(first.plainTextKey == third.plainTextKey)
}

// TestCryptoEngineCacheKeyFaults verifies that every way the unwrap can fail is reported as
// an encryption failure naming the step which failed.
func TestCryptoEngineCacheKeyFaults(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	injected := errors.New("cgoutils failure")

	tests := []struct {
		name    string
		wire    func(*testing.T, *mockcrypto.Engine)
		expects string
	}{
		{
			name: "RSA unwrap fails",
			wire: func(_ *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On(
					"RSADecrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
				).Return(nil, injected).Once()
			},
			expects: "failed to decrypt symmetric key",
		},
		{
			name: "secure buffer allocation fails",
			wire: func(_ *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("AllocateSecureCSlice", mock.AnythingOfType("int")).
					Return(nil, injected).Once()
			},
			expects: "failed to allocate secure buffer for key",
		},
		{
			name: "secure buffer is unreadable",
			wire: func(t *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("AllocateSecureCSlice", mock.AnythingOfType("int")).Return(
					newHealthySecureCSlice(
						t, testAEADKeyLen, func(buffer *mockcrypto.SecureCSlice) {
							buffer.On("GetSlice").Return(nil, injected).Once()
						},
					),
					nil,
				).Once()
			},
			expects: "failed to access secure buffer core for key",
		},
		{
			name: "secure buffer is too small for the key",
			wire: func(t *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("AllocateSecureCSlice", mock.AnythingOfType("int")).
					Return(newHealthySecureCSlice(t, testAEADKeyLen/2), nil).Once()
			},
			expects: "failed to fill secure buffer for key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)

			uut, mockCrypto := newMockedCryptoEngine(t)
			// Registered ahead of the healthy defaults, so the fault is what the engine meets
			test.wire(t, mockCrypto)
			expectHealthyCryptoCalls(t, mockCrypto, newHealthyAEAD(t))

			entry, err := uut.cacheKey(utCtx, testCacheableKey(uut.kek.ID()))
			assert.Error(err)
			assert.ErrorContains(err, test.expects)
			assert.Nil(entry.plainTextKey)

			var encryptionErr models.EncryptionError
			assert.True(errors.As(err, &encryptionErr))
		})
	}
}

// TestCryptoEngineNewEncryptionKeyFaults verifies that a key is never recorded when any step
// of minting it fails.
//
// Every fault here lands before persistence is touched, so the database mock carrying no
// expectations is itself the assertion: a half-minted key must not reach the table.
func TestCryptoEngineNewEncryptionKeyFaults(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	injected := errors.New("cgoutils failure")

	tests := []struct {
		name    string
		wire    func(*testing.T, *mockcrypto.Engine)
		expects string
	}{
		{
			name: "AEAD unavailable",
			wire: func(_ *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("GetAEAD", mock.Anything, mock.Anything).
					Return(nil, injected).Once()
			},
			expects: "unable to define AEAD client",
		},
		{
			name: "key material cannot be drawn",
			wire: func(_ *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("GetRandomBuf", mock.Anything, mock.AnythingOfType("int")).
					Return(nil, injected).Once()
			},
			expects: "failed to generate 32 byte key",
		},
		{
			name: "drawn key is unreadable",
			wire: func(t *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("GetRandomBuf", mock.Anything, mock.AnythingOfType("int")).Return(
					newHealthySecureCSlice(
						t, testAEADKeyLen, func(buffer *mockcrypto.SecureCSlice) {
							buffer.On("GetSlice").Return(nil, injected).Once()
						},
					),
					nil,
				).Once()
			},
			expects: "failed to access new key buffer core",
		},
		{
			name: "key cannot be wrapped",
			wire: func(_ *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On(
					"RSAEncrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
				).Return(nil, injected).Once()
			},
			expects: "failed to encrypt symmetric enc key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := assert.New(t)

			uut, mockCrypto := newMockedCryptoEngine(t)
			test.wire(t, mockCrypto)
			expectHealthyCryptoCalls(t, mockCrypto, newHealthyAEAD(t))

			_, err := uut.NewEncryptionKey(utCtx, mockdb.NewDatabase(t))
			assert.Error(err)
			assert.ErrorContains(err, test.expects)

			var encryptionErr models.EncryptionError
			assert.True(errors.As(err, &encryptionErr))
		})
	}
}
