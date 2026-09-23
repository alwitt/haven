package encryption

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cgoCrypto "github.com/alwitt/cgoutils/crypto"
	mockcrypto "github.com/alwitt/cgoutils/mocks/crypto"
	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// The XChaCha20-Poly1305 sizes the engine asks the AEAD for
const (
	testAEADNonceLen = 24
	testAEADKeyLen   = 32
	testAEADTagLen   = 16
)

// testKEK load a primary RSA key pair from the certificate fixtures
//
// The key pair is read with the standard library rather than through LoadKEK, so an engine
// whose cgoutils calls are mocked still holds a usable one. The ID comes from kekIDOf, so it
// is the same ID LoadKEK derives for this key.
func testKEK(t *testing.T, certName, keyName string) KEK {
	assert := assert.New(t)

	certPEM, err := os.ReadFile(filepath.Join("..", "test", "certs", certName))
	assert.Nil(err)
	keyPEM, err := os.ReadFile(filepath.Join("..", "test", "certs", keyName))
	assert.Nil(err)

	certBlock, _ := pem.Decode(certPEM)
	assert.NotNil(certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	assert.Nil(err)
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	assert.True(ok)

	keyBlock, _ := pem.Decode(keyPEM)
	assert.NotNil(keyBlock)
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	assert.Nil(err)
	privKey, ok := parsedKey.(*rsa.PrivateKey)
	assert.True(ok)

	kekID, err := kekIDOf(pubKey)
	assert.Nil(err)

	return KEK{privateKey: privKey, publicKey: pubKey, id: kekID}
}

// newMockedCryptoEngine build an engine whose every cgoutils call is mocked, so a failure
// can be injected at any one of them
//
// persistence is left nil: every test drives the engine with an explicit database client, so
// ActiveSessionWrapper never reaches for one.
func newMockedCryptoEngine(t *testing.T) (*cryptoEngine, *mockcrypto.Engine) {
	assert := assert.New(t)

	mockCrypto := mockcrypto.NewEngine(t)

	instance := &cryptoEngine{
		Component: goutils.Component{
			LogTags: log.Fields{
				"package": "haven", "module": "encryption", "component": "crypto-engine",
			},
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
			},
		},
		validator:    validator.New(),
		crypto:       mockCrypto,
		kek:          testKEK(t, "self-signed.crt", "self-signed.key"),
		keyCacheTTL:  time.Hour,
		keyCacheLock: &sync.RWMutex{},
		encKeys:      make(map[string]encKeyCacheEntry),
	}
	assert.Nil(models.RegisterWithValidator(instance.validator))

	return instance, mockCrypto
}

// Every builder below takes its faults first and registers the healthy behaviour after.
// testify serves the earliest matching expectation, so a fault a test registers through
// these takes precedence over the default it replaces.

// newHealthySecureCSlice a secure buffer mock backed by a real slice of the given length
func newHealthySecureCSlice(
	t *testing.T, length int, faults ...func(*mockcrypto.SecureCSlice),
) *mockcrypto.SecureCSlice {
	buffer := mockcrypto.NewSecureCSlice(t)
	for _, fault := range faults {
		fault(buffer)
	}

	backing := make([]byte, length)
	buffer.On("GetSlice").Return(backing, nil).Maybe()
	buffer.On("GetLen").Return(length, nil).Maybe()
	buffer.On("Zero").Return(nil).Maybe()

	return buffer
}

// newHealthyAEAD an AEAD mock sized for XChaCha20-Poly1305 which succeeds at every operation
func newHealthyAEAD(t *testing.T, faults ...func(*mockcrypto.AEAD)) *mockcrypto.AEAD {
	aead := mockcrypto.NewAEAD(t)
	for _, fault := range faults {
		fault(aead)
	}

	aead.On("ExpectedNonceLen").Return(testAEADNonceLen).Maybe()
	aead.On("ExpectedKeyLen").Return(testAEADKeyLen).Maybe()
	aead.On("ExpectedCipherLen", mock.AnythingOfType("int64")).Return(
		func(plainLen int64) int64 { return plainLen + testAEADTagLen },
	).Maybe()
	aead.On("ExpectedPlainTextLen", mock.AnythingOfType("int64")).Return(
		func(cipherLen int64) int64 { return cipherLen - testAEADTagLen },
	).Maybe()
	aead.On("SetKey", mock.Anything).Return(nil).Maybe()
	aead.On("SetNonce", mock.Anything).Return(nil).Maybe()
	aead.On("Nonce").Return(func() cgoCrypto.SecureCSlice {
		return newHealthySecureCSlice(t, testAEADNonceLen)
	}).Maybe()
	aead.On(
		"Seal", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(nil).Maybe()
	aead.On(
		"Unseal", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(nil).Maybe()

	return aead
}

// expectHealthyCryptoCalls wire the engine mock to succeed at every call the encryption
// paths make, so a test registers only the failure it is asserting
//
// The AEAD is supplied so one test can hold a reference to the instance the engine will be
// handed.
func expectHealthyCryptoCalls(
	t *testing.T, mockCrypto *mockcrypto.Engine, aead *mockcrypto.AEAD,
) {
	newBuffer := func(length int) cgoCrypto.SecureCSlice {
		return newHealthySecureCSlice(t, length)
	}

	mockCrypto.On("GetAEAD", mock.Anything, mock.Anything).Return(aead, nil).Maybe()
	mockCrypto.On("GetRandomBuf", mock.Anything, mock.AnythingOfType("int")).Return(
		func(_ context.Context, length int) cgoCrypto.SecureCSlice { return newBuffer(length) },
		nil,
	).Maybe()
	mockCrypto.On("AllocateSecureCSlice", mock.AnythingOfType("int")).Return(
		func(length int) cgoCrypto.SecureCSlice { return newBuffer(length) }, nil,
	).Maybe()
	mockCrypto.On(
		"RSAEncrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return([]byte("wrapped-key-material"), nil).Maybe()
	mockCrypto.On(
		"RSADecrypt", mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Return(make([]byte, testAEADKeyLen), nil).Maybe()
}
