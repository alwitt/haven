// Package encryption - data encryption processing engine
package encryption

import (
	"context"
	"crypto/rsa"
	"fmt"
	"sync"

	cgoCrypto "github.com/alwitt/cgoutils/crypto"
	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
)

/*
CryptographyEngine the system's cryptography engine. It is solely responsible for all
cryptographic operations in the system.

Aside from performing the cryptographic computation, it also provides the wrapper
interface around the encryption related APIs in the persistence layer. (i.e. the rest
of the system must not directly interact with the encryption key APIs of the persistence
layer.)
*/
type CryptographyEngine interface {
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

	/*
		MarkEncryptionKeyActive mark encryption key is active

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
			@param activeDBClient Database - existing database transaction
	*/
	MarkEncryptionKeyActive(ctx context.Context, keyID string, activeDBClient db.Database) error

	/*
		MarkEncryptionKeyInactive mark encryption key is inactive

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
			@param activeDBClient Database - existing database transaction
	*/
	MarkEncryptionKeyInactive(ctx context.Context, keyID string, activeDBClient db.Database) error

	/*
		DeleteEncryptionKey delete encryption key

			@param ctx context.Context - execution context
			@param keyID string - the encryption key ID
			@param activeDBClient Database - existing database transaction
	*/
	DeleteEncryptionKey(ctx context.Context, keyID string, activeDBClient db.Database) error
}

// cryptoEngine implements CryptographyEngine
type cryptoEngine struct {
	goutils.Component

	persistence db.Client
	validator   *validator.Validate

	crypto cgoCrypto.Engine

	rsaKey    *rsa.PrivateKey
	rsaPubKey *rsa.PublicKey

	keyCacheLock *sync.RWMutex
	encKeys      map[string]encKeyCacheEntry
}

// encKeyCacheEntry system encryption key cache entry
type encKeyCacheEntry struct {
	models.EncryptionKey
	// plainTextKey the decrypted symmetric encryption key
	plainTextKey []byte
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
		return nil, fmt.Errorf("failed to prepare core cryptography [%w]", err)
	}

	logTags := log.Fields{"module": "encryption", "component": "crypto-engine"}

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
		keyCacheLock: &sync.RWMutex{},
		encKeys:      make(map[string]encKeyCacheEntry),
	}
	if err := models.RegisterWithValidator(instance.validator); err != nil {
		return nil, fmt.Errorf("failed to install custom validation macros [%w]", err)
	}

	// Load the primary RSA certificate and private key
	if err := instance.validator.Struct(&params); err != nil {
		return nil, fmt.Errorf("invalid engine init parameters [%w]", err)
	}
	if err := instance.loadRSAKeyPair(
		ctx, params.PrimaryRSACertFile, params.PrimaryRSAKeyFile,
	); err != nil {
		return nil, fmt.Errorf("failed to load primary RSA key pair [%w]", err)
	}

	return instance, nil
}
