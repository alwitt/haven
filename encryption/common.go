// Package encryption - data encryption processing engine
package encryption

import (
	"context"
	"crypto/rsa"
	"sync"
	"time"

	cgoCrypto "github.com/alwitt/cgoutils/crypto"
	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

// EncryptedData helper function to group encryption data together
type EncryptedData struct {
	// CipherText the cipher text
	CipherText []byte
	// Nonce the nonce
	Nonce []byte
}

// KEK a loaded primary RSA key pair, the key encryption key which wraps every symmetric
// encryption key
//
// The fields are unexported so the private key never leaves this package.
type KEK struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	id         string
}

// ID the ID stamped on every encryption key this key pair wraps
func (k KEK) ID() string {
	return k.id
}

// KEKParams file paths to a primary RSA key pair
type KEKParams struct {
	// CertFile file path to the RSA certificate PEM
	CertFile string `validate:"required,file"`
	// KeyFile file path to the RSA certificate private key PEM
	KeyFile string `validate:"required,file"`
	// CACertFile file path to a PEM bundle of the CA certificates that issued the
	// certificate. When set, the certificate must chain to a self-signed root in the bundle
	// through any intermediates the bundle also holds. When nil, only the certificate's
	// validity window is checked. Revocation is never checked.
	CACertFile *string `validate:"omitempty,file"`
}

/*
CryptographyEngine the system's cryptography engine. It is solely responsible for all
cryptographic operations in the system.

It is the only component which holds the primary RSA key pair, and the only one which
wraps or unwraps symmetric key material. The steady-state data path reaches encryption
keys only through here; key state and key deletion belong to maintenance actions, which
drive them through the persistence layer directly.

The maintenance surface covers everything a rotation does which is cryptographic: moving
record versions between encryption keys, and re-wrapping encryption keys under a new
primary RSA key pair. Paging, transaction boundaries and the system state transitions
around them belong to the caller.

Encryption keys which can still decrypt are cached in-process, with their decrypted key
material held in libsodium secure memory. A cached entry is trusted for `KeyCacheTTL`
before it is re-validated against persistence, so a key state change made by another engine
instance on the same database becomes visible here only after the TTL lapses. State changes
made through this instance take effect in the cache immediately.
*/
type CryptographyEngine interface {
	// ------------------------------------------------------------------------------------
	// Primary RSA key pair

	/*
		KEKID the ID of the primary RSA key pair this engine is configured with

			@returns the key pair ID
	*/
	KEKID() string

	/*
		LoadKEK load a primary RSA key pair without adopting it

		The engine keeps the key pair it was constructed with. A KEK rotation needs a second
		one to wrap with, while the first stays in place to unwrap the keys not yet converted.

			@param ctx context.Context - execution context
			@param params KEKParams - the key pair file paths
			@returns the loaded key pair
	*/
	LoadKEK(ctx context.Context, params KEKParams) (KEK, error)

	// ------------------------------------------------------------------------------------
	// Encryption key management

	/*
	   NewEncryptionKey define a new encryption symmetric encryption key

	   	@param ctx context.Context - execution context
	   	@param activeDBClient Database - existing database transaction
	   	@returns the key entry
	*/
	NewEncryptionKey(ctx context.Context, activeDBClient db.Database) (models.EncryptionKey, error)

	/*
		GetEncryptionKey fetch one encryption key

		Served from the key cache when a fresh entry exists; otherwise read from persistence.

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
			@param activeDBClient Database - existing database transaction
			@return key entry
	*/
	GetEncryptionKey(
		ctx context.Context, keyID string, activeDBClient db.Database,
	) (models.EncryptionKey, error)

	/*
		ListEncryptionKeys list encryption keys

			@param ctx context.Context - execution context
			@param filters EncryptionKeyQueryFilter - entry listing filter
			@param activeDBClient Database - existing database transaction
			@return list of keys
	*/
	ListEncryptionKeys(
		ctx context.Context, filters db.EncryptionKeyQueryFilter, activeDBClient db.Database,
	) ([]models.EncryptionKey, error)

	// ------------------------------------------------------------------------------------
	// Data encryption

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
	EncryptData(
		ctx context.Context,
		keyID string,
		plainText []byte,
		additional []byte,
		activeDBClient db.Database,
	) (models.EncryptionKey, EncryptedData, error)

	/*
		DecryptData decrypt cipher text

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
			@param encrypted EncryptedData - the cipher text to decrypt
			@param additional []byte - the associated data supplied when encrypting
			@param activeDBClient Database - existing database transaction
			@return key entry for the encryption, and the plain text
	*/
	DecryptData(
		ctx context.Context,
		keyID string,
		encrypted EncryptedData,
		additional []byte,
		activeDBClient db.Database,
	) (models.EncryptionKey, []byte, error)

	// ------------------------------------------------------------------------------------
	// Maintenance actions

	/*
		ReEncryptRecordVersions move record versions onto a different encryption key

		Each version is decrypted under the key which currently holds it, and re-sealed under
		the target key with a fresh nonce and the associated data recomputed from the new key
		ID. The version keeps its ID, its record and its place in the record's history; only
		the encryption columns change.

		Halts on the first version which will not decrypt, returning an UndecryptableVersion
		and converting nothing further.

			@param ctx context.Context - execution context
			@param versions []models.RecordVersion - the versions to move
			@param targetKey models.EncryptionKey - the key to move them onto
			@param activeDBClient Database - existing database transaction
	*/
	ReEncryptRecordVersions(
		ctx context.Context,
		versions []models.RecordVersion,
		targetKey models.EncryptionKey,
		activeDBClient db.Database,
	) error

	/*
		FindUndecryptableVersions report which record versions will not decrypt

		Read only: it attempts to decrypt each version and converts nothing. This sizes the
		damage after ReEncryptRecordVersions halts, so an operator can choose between
		restoring the rows from a backup and destroying them.

			@param ctx context.Context - execution context
			@param versions []models.RecordVersion - the versions to check
			@param activeDBClient Database - existing database transaction
			@returns one finding per version which failed to decrypt
	*/
	FindUndecryptableVersions(
		ctx context.Context,
		versions []models.RecordVersion,
		activeDBClient db.Database,
	) ([]UndecryptableVersion, error)

	/*
		RewrapEncryptionKeys re-wrap encryption keys under a different primary RSA key pair

		Each key's material is unwrapped with the key pair this engine holds and re-wrapped
		under the given one. The symmetric key itself is unchanged, so every record version
		encrypted with it stays valid and none are touched.

		Keys already carrying the new key pair's ID are skipped, which is what lets an
		interrupted KEK rotation resume.

			@param ctx context.Context - execution context
			@param keys []models.EncryptionKey - the keys to re-wrap
			@param newKEK KEK - the key pair to re-wrap them under
			@param activeDBClient Database - existing database transaction
	*/
	RewrapEncryptionKeys(
		ctx context.Context,
		keys []models.EncryptionKey,
		newKEK KEK,
		activeDBClient db.Database,
	) error
}

// cryptoEngine implements CryptographyEngine
type cryptoEngine struct {
	goutils.Component

	persistence db.Client
	validator   *validator.Validate

	crypto cgoCrypto.Engine

	// kek the primary RSA key pair this engine is configured with. A KEK rotation loads a
	// second one, which is passed in rather than adopted here.
	kek KEK

	keyCacheTTL  time.Duration
	keyCacheLock *sync.RWMutex
	encKeys      map[string]encKeyCacheEntry
}

// encKeyCacheEntry system encryption key cache entry
type encKeyCacheEntry struct {
	models.EncryptionKey
	// plainTextKey the decrypted symmetric encryption key, held in libsodium secure memory
	plainTextKey cgoCrypto.SecureCSlice
	// expiresAt the entry must be re-validated against persistence after this instant
	expiresAt time.Time
}

// CryptographyEngineParams cryptography engine init parameters
//
// The primary RSA key pair is used to encrypt and decrypt symmetric encryption keys
type CryptographyEngineParams struct {
	// Persistence persistence layer client
	Persistence db.Client `validate:"-"`
	// PrimaryRSACertFile file path to the primary RSA certificate PEM
	PrimaryRSACertFile string `validate:"required,file"`
	// PrimaryRSAKeyFile file path to the primary RSA certificate private key PEM
	PrimaryRSAKeyFile string `validate:"required,file"`
	// PrimaryRSACACertFile file path to a PEM bundle of the CA certificates that issued the
	// primary RSA certificate. When set, the certificate must chain to a self-signed root in
	// the bundle through any intermediates the bundle also holds. When nil, only the
	// certificate's validity window is checked. Revocation is never checked.
	PrimaryRSACACertFile *string `validate:"omitempty,file"`
	// KeyCacheTTL how long a cached encryption key is trusted before it is re-validated
	// against persistence. 0 re-validates on every use.
	KeyCacheTTL time.Duration `validate:"gte=0"`
}

// kekParams the primary RSA key pair file paths, as LoadKEK takes them
func (p CryptographyEngineParams) kekParams() KEKParams {
	return KEKParams{
		CertFile:   p.PrimaryRSACertFile,
		KeyFile:    p.PrimaryRSAKeyFile,
		CACertFile: p.PrimaryRSACACertFile,
	}
}

/*
NewCryptographyEngine define new cryptography engine

	@param ctx context.Context - execution context
	@param params CryptographyEngineParams - engine parameters
	@returns engine instance
*/
func NewCryptographyEngine(
	ctx context.Context, params CryptographyEngineParams,
) (CryptographyEngine, error) {
	// Prepare core crypto engine
	engine, err := cgoCrypto.NewEngine(log.Fields{
		"package": "cgoutils", "module": "crypto", "component": "crypto-engine",
	})

	if err != nil {
		return nil, models.NewEncryptionError("failed to prepare core cryptography", err, true)
	}

	logTags := log.Fields{
		"package": "haven", "module": "encryption", "component": "crypto-engine",
	}

	instance := &cryptoEngine{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
			},
		},
		persistence:  params.Persistence,
		validator:    validator.New(),
		crypto:       engine,
		keyCacheTTL:  params.KeyCacheTTL,
		keyCacheLock: &sync.RWMutex{},
		encKeys:      make(map[string]encKeyCacheEntry),
	}
	if err := models.RegisterWithValidator(instance.validator); err != nil {
		return nil, models.NewEncryptionError("failed to install custom validation macros", err, true)
	}

	// Load the primary RSA certificate and private key
	if err := instance.validator.Struct(&params); err != nil {
		return nil, goutils.NewValidationError("invalid engine init parameters", err, true)
	}
	kek, err := instance.LoadKEK(ctx, params.kekParams())
	if err != nil {
		return nil, models.NewEncryptionError("failed to load primary RSA key pair", err, true)
	}
	instance.kek = kek

	return instance, nil
}
