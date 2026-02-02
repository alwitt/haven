// Package haven - encrypted-at-rest simple data storage
package haven

import (
	"context"
	"fmt"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	"github.com/alwitt/haven/store"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

/*
NewProtectedKVStore initialize a protected KV store instance.

Each instance is backed by a SQL database; two instances using the same database are
essentially copies of each other.

	@param ctx context.Context - execution context
	@param dbDialector gorm.Dialector - GORM dialector
	@param dbLogLevel logger.LogLevel - SQL log level
	@param primaryRSACertFile string - file path to the primary RSA certificate PEM
	@param primaryRSAKeyFile string - file path to the primary RSA certificate private key PEM
	@returns new store instance
*/
func NewProtectedKVStore(
	ctx context.Context,
	dbDialector gorm.Dialector,
	dbLogLevel logger.LogLevel,
	primaryRSACertFile string,
	primaryRSAKeyFile string,
) (store.ProtectedKVStore, error) {
	// Prepare persistence
	persistence, err := db.NewConnection(dbDialector, dbLogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to initialized persistence client [%w]", err)
	}

	// Prepare cryptography engine
	cryptoEngine, err := encryption.NewCryptographyEngine(ctx, encryption.CryptographyEngineParams{
		Persistence:        persistence,
		PrimaryRSACertFile: primaryRSACertFile,
		PrimaryRSAKeyFile:  primaryRSAKeyFile,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialized cryptography engine [%w]", err)
	}

	store, err := store.NewProtectedKVStore(ctx, persistence, cryptoEngine)
	if err != nil {
		return nil, fmt.Errorf("failed to initialized protected KV store [%w]", err)
	}

	return store, nil
}
