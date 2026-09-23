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

// seedCachedKey place a usable key in the engine's cache, so an encrypt or decrypt reaches
// the AEAD without a persistence round trip
func seedCachedKey(t *testing.T, uut *cryptoEngine) models.EncryptionKey {
	keyEntry := testCacheableKey(uut.kek.ID())
	uut.writeKeyToCache(keyEntry, newHealthySecureCSlice(t, testAEADKeyLen))
	return keyEntry
}

// cryptoFault one way a cgoutils call can fail during an encrypt or decrypt
type cryptoFault struct {
	name string
	// aead a failure in the AEAD the engine is handed
	aead func(*mockcrypto.AEAD)
	// engine a failure in the cryptography engine itself
	engine func(*testing.T, *mockcrypto.Engine)
	// expects the text the returned error must carry, naming the step which failed
	expects string
}

// runCryptoFault drive one fault case, with the failure registered ahead of the healthy
// defaults so it is what the engine meets
func runCryptoFault(
	t *testing.T,
	fault cryptoFault,
	drive func(*cryptoEngine, models.EncryptionKey) error,
) {
	assert := assert.New(t)

	aeadFaults := []func(*mockcrypto.AEAD){}
	if fault.aead != nil {
		aeadFaults = append(aeadFaults, fault.aead)
	}
	aead := newHealthyAEAD(t, aeadFaults...)

	uut, mockCrypto := newMockedCryptoEngine(t)
	if fault.engine != nil {
		fault.engine(t, mockCrypto)
	}
	expectHealthyCryptoCalls(t, mockCrypto, aead)

	err := drive(uut, seedCachedKey(t, uut))
	assert.Error(err)
	assert.ErrorContains(err, fault.expects)

	var encryptionErr models.EncryptionError
	assert.True(errors.As(err, &encryptionErr))
}

// TestCryptoEngineEncryptDataFaults verifies that every cgoutils failure on the encrypt path
// is reported as an encryption failure naming the step which failed.
//
// The nonce is drawn here rather than supplied, so this covers the generated-nonce half of
// setupAEAD along with the sealing itself.
func TestCryptoEngineEncryptDataFaults(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	injected := errors.New("cgoutils failure")

	tests := []cryptoFault{
		{
			name: "AEAD unavailable",
			engine: func(_ *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("GetAEAD", mock.Anything, mock.Anything).
					Return(nil, injected).Once()
			},
			expects: "unable to define AEAD client",
		},
		{
			name: "key will not install",
			aead: func(aead *mockcrypto.AEAD) {
				aead.On("SetKey", mock.Anything).Return(injected).Once()
			},
			expects: "failed to install AEAD key",
		},
		{
			name: "nonce cannot be drawn",
			engine: func(_ *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("GetRandomBuf", mock.Anything, mock.AnythingOfType("int")).
					Return(nil, injected).Once()
			},
			expects: "failed to init AEAD nonce",
		},
		{
			name: "nonce will not install",
			aead: func(aead *mockcrypto.AEAD) {
				aead.On("SetNonce", mock.Anything).Return(injected).Once()
			},
			expects: "failed to install AEAD nonce",
		},
		{
			name: "nonce is unreadable",
			aead: func(aead *mockcrypto.AEAD) {
				buffer := mockcrypto.NewSecureCSlice(t)
				buffer.On("GetSlice").Return(nil, injected).Once()
				aead.On("Nonce").Return(buffer).Once()
			},
			expects: "failed to get nonce",
		},
		{
			name: "nonce is shorter than the AEAD expects",
			aead: func(aead *mockcrypto.AEAD) {
				aead.On("Nonce").
					Return(newHealthySecureCSlice(t, testAEADNonceLen/2)).Once()
			},
			expects: "failed to copy nonce",
		},
		{
			name: "sealing fails",
			aead: func(aead *mockcrypto.AEAD) {
				aead.On(
					"Seal", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
				).Return(injected).Once()
			},
			expects: "failed to encrypt plain text",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runCryptoFault(t, test, func(uut *cryptoEngine, key models.EncryptionKey) error {
				_, _, err := uut.EncryptData(
					utCtx, key.ID, []byte("plain text"), []byte("associated"), mockdb.NewDatabase(t),
				)
				return err
			})
		})
	}
}

// TestCryptoEngineDecryptDataFaults verifies the same for the decrypt path.
//
// The nonce is supplied from the row, so this covers the half of setupAEAD which installs an
// existing nonce — the half a rotation and every read go through.
func TestCryptoEngineDecryptDataFaults(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	injected := errors.New("cgoutils failure")

	encrypted := EncryptedData{
		CipherText: make([]byte, 64), Nonce: make([]byte, testAEADNonceLen),
	}

	tests := []cryptoFault{
		{
			name: "nonce buffer cannot be allocated",
			engine: func(_ *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("AllocateSecureCSlice", mock.AnythingOfType("int")).
					Return(nil, injected).Once()
			},
			expects: "failed to init AEAD nonce buffer",
		},
		{
			name: "nonce buffer is unreadable",
			engine: func(t *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("AllocateSecureCSlice", mock.AnythingOfType("int")).Return(
					newHealthySecureCSlice(
						t, testAEADNonceLen, func(buffer *mockcrypto.SecureCSlice) {
							buffer.On("GetSlice").Return(nil, injected).Once()
						},
					),
					nil,
				).Once()
			},
			expects: "failed to access AEAD nonce buffer core",
		},
		{
			name: "nonce buffer is too small for the nonce",
			engine: func(t *testing.T, mockCrypto *mockcrypto.Engine) {
				mockCrypto.On("AllocateSecureCSlice", mock.AnythingOfType("int")).
					Return(newHealthySecureCSlice(t, testAEADNonceLen/2), nil).Once()
			},
			expects: "failed to fill AEAD nonce buffer core",
		},
		{
			name: "nonce will not install",
			aead: func(aead *mockcrypto.AEAD) {
				aead.On("SetNonce", mock.Anything).Return(injected).Once()
			},
			expects: "failed to install AEAD nonce",
		},
		{
			name: "unsealing fails",
			aead: func(aead *mockcrypto.AEAD) {
				aead.On(
					"Unseal", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
				).Return(injected).Once()
			},
			expects: "failed to decrypt cipher text",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runCryptoFault(t, test, func(uut *cryptoEngine, key models.EncryptionKey) error {
				_, _, err := uut.DecryptData(
					utCtx, key.ID, encrypted, []byte("associated"), mockdb.NewDatabase(t),
				)
				return err
			})
		})
	}
}

// TestCryptoEngineDecryptDataRejectsShortCipherText verifies that a cipher text holding
// nothing beyond the authentication tag is refused before it reaches the AEAD.
//
// The AEAD reports a plain text length of zero or less for such a row, and allocating a
// buffer from that panics. A corrupted row must not be able to do that.
func TestCryptoEngineDecryptDataRejectsShortCipherText(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	uut, mockCrypto := newMockedCryptoEngine(t)
	expectHealthyCryptoCalls(t, mockCrypto, newHealthyAEAD(t))
	keyEntry := seedCachedKey(t, uut)

	_, _, err := uut.DecryptData(
		utCtx,
		keyEntry.ID,
		EncryptedData{
			CipherText: make([]byte, testAEADTagLen), Nonce: make([]byte, testAEADNonceLen),
		},
		[]byte("associated"),
		mockdb.NewDatabase(t),
	)
	assert.Error(err)
	assert.ErrorContains(err, "cipher text too short")

	var encryptionErr models.EncryptionError
	assert.True(errors.As(err, &encryptionErr))
}

// TestCryptoEngineEncryptDataRejectsUnusableKey verifies that a key which cannot encrypt is
// refused before any AEAD work, and names the state which refused it.
func TestCryptoEngineEncryptDataRejectsUnusableKey(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()

	uut, mockCrypto := newMockedCryptoEngine(t)
	expectHealthyCryptoCalls(t, mockCrypto, newHealthyAEAD(t))

	// A retired key decrypts, so it stays cached, but it may not take new data
	retired := testCacheableKey(uut.kek.ID())
	retired.ID = uuid.NewString()
	retired.State = models.EncryptionKeyStateRetired
	uut.writeKeyToCache(retired, newHealthySecureCSlice(t, testAEADKeyLen))

	_, _, err := uut.EncryptData(
		utCtx, retired.ID, []byte("plain text"), nil, mockdb.NewDatabase(t),
	)
	assert.Error(err)
	assert.ErrorContains(err, "can't encrypt")
	assert.ErrorContains(err, string(models.EncryptionKeyStateRetired))
}
