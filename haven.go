// Package haven - encrypted-at-rest simple data storage
package haven

import (
	"context"
	"fmt"
	"time"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	"github.com/alwitt/haven/maintenance"
	"github.com/alwitt/haven/store"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ProtectedKVStoreParams protected KV store init parameters
type ProtectedKVStoreParams struct {
	// DBDialector GORM dialector
	DBDialector gorm.Dialector
	// DBLogLevel SQL log level
	DBLogLevel logger.LogLevel
	// PrimaryRSACertFile file path to the primary RSA certificate PEM
	PrimaryRSACertFile string
	// PrimaryRSAKeyFile file path to the primary RSA certificate private key PEM
	PrimaryRSAKeyFile string
	// PrimaryRSACACertFile file path to a PEM bundle of the CA certificates that issued the
	// primary RSA certificate. When set, the certificate must chain to a self-signed root in
	// the bundle through any intermediates the bundle also holds. When nil, only the
	// certificate's validity window is checked. Revocation is never checked.
	PrimaryRSACACertFile *string
	// KeyCacheTTL how long a cached encryption key is trusted before it is re-validated
	// against persistence. 0 re-validates on every use.
	KeyCacheTTL time.Duration
}

/*
NewProtectedKVStore initialize a protected KV store instance.

Each instance is backed by a SQL database; two instances using the same database are
essentially copies of each other.

	@param ctx context.Context - execution context
	@param params ProtectedKVStoreParams - store parameters
	@returns new store instance and a persistence layer handle for direct read
*/
func NewProtectedKVStore(
	ctx context.Context, params ProtectedKVStoreParams,
) (store.ProtectedKVStore, db.Client, error) {
	// Prepare persistence
	persistence, err := db.NewConnection(params.DBDialector, params.DBLogLevel)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialized persistence client [%w]", err)
	}

	// Prepare cryptography engine
	cryptoEngine, err := encryption.NewCryptographyEngine(ctx, encryption.CryptographyEngineParams{
		Persistence:          persistence,
		PrimaryRSACertFile:   params.PrimaryRSACertFile,
		PrimaryRSAKeyFile:    params.PrimaryRSAKeyFile,
		PrimaryRSACACertFile: params.PrimaryRSACACertFile,
		KeyCacheTTL:          params.KeyCacheTTL,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialized cryptography engine [%w]", err)
	}

	store, err := store.NewProtectedKVStore(ctx, persistence, cryptoEngine)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialized protected KV store [%w]", err)
	}

	return store, persistence, nil
}

/*
NewMaintenanceRunner initialize a maintenance action runner.

The runner performs the operations which change the store's cryptographic material:
preparing a new store for use, rotating the encryption key, and rotating the primary RSA
key pair. No instance of the embedding application may run while one is in progress.

	@param ctx context.Context - execution context
	@param params ProtectedKVStoreParams - store parameters, naming the key pair in use
	@param pageSize int - how many entries a maintenance action converts per transaction.
	    Defaults when <= 0.
	@returns new runner instance and a persistence layer handle for direct read
*/
func NewMaintenanceRunner(
	ctx context.Context, params ProtectedKVStoreParams, pageSize int,
) (maintenance.Runner, db.Client, error) {
	// Prepare persistence
	persistence, err := db.NewConnection(params.DBDialector, params.DBLogLevel)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialized persistence client [%w]", err)
	}

	// Prepare cryptography engine
	cryptoEngine, err := encryption.NewCryptographyEngine(ctx, encryption.CryptographyEngineParams{
		Persistence:          persistence,
		PrimaryRSACertFile:   params.PrimaryRSACertFile,
		PrimaryRSAKeyFile:    params.PrimaryRSAKeyFile,
		PrimaryRSACACertFile: params.PrimaryRSACACertFile,
		KeyCacheTTL:          params.KeyCacheTTL,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialized cryptography engine [%w]", err)
	}

	runner, err := maintenance.NewRunner(ctx, persistence, cryptoEngine, pageSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialized maintenance runner [%w]", err)
	}

	return runner, persistence, nil
}
