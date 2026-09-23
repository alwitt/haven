// Package models - system data models
package models

import (
	"fmt"
	"time"

	"github.com/alwitt/goutils"
)

// EncryptionKeyStateENUMType encryption state enum type
type EncryptionKeyStateENUMType string

const (
	// EncryptionKeyStateActive the encryption key encrypts new data, and decrypts
	EncryptionKeyStateActive EncryptionKeyStateENUMType = "ACTIVE"
	// EncryptionKeyStateRetired the encryption key only decrypts. A key is retired while a
	// rotation moves the data it protects onto the new active key.
	EncryptionKeyStateRetired EncryptionKeyStateENUMType = "RETIRED"
)

// Values all valid EncryptionKeyStateENUMType values
func (EncryptionKeyStateENUMType) Values() []EncryptionKeyStateENUMType {
	return []EncryptionKeyStateENUMType{
		EncryptionKeyStateActive,
		EncryptionKeyStateRetired,
	}
}

// CanEncrypt whether a key in this state may encrypt new data
func (s EncryptionKeyStateENUMType) CanEncrypt() bool {
	return s == EncryptionKeyStateActive
}

// CanDecrypt whether a key in this state may decrypt existing data
//
// A retired key still decrypts: it is the state a key occupies while a rotation moves the
// data it protects onto the new active key, and that rotation must read that data.
func (s EncryptionKeyStateENUMType) CanDecrypt() bool {
	return s == EncryptionKeyStateActive || s == EncryptionKeyStateRetired
}

// EncryptionKey an encryption key used to encrypt record value
//
// These encryption keys are meant to be used for symmetric encryption
type EncryptionKey struct {
	// ID key ID
	ID string `json:"id" gorm:"column:id;primaryKey;unique" validate:"required,uuid_rfc4122"`

	// EncKeyMaterial the encrypted encryption key material
	EncKeyMaterial []byte `json:"enc_key_material" gorm:"column:enc_key_material;not null" validate:"required"`

	// KekID identifies the primary RSA key pair which encrypted EncKeyMaterial. It is the
	// hex SHA-256 of that public key's SPKI DER, so it survives certificate renewal and
	// changes only when the key pair itself does.
	KekID string `json:"kek_id" gorm:"column:kek_id;not null" validate:"required"`

	// State the encryption key state
	State EncryptionKeyStateENUMType `json:"state" gorm:"column:state;not null" validate:"required,enc_key_state"`

	// CreatedAt entry creation timestamp
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt entry update timestamp
	UpdatedAt time.Time `json:"updated_at"`
}

// ValidateNextState verify can transition to new state
func (e *EncryptionKey) ValidateNextState(newState EncryptionKeyStateENUMType) error {
	// Retirement is one way: a rotation always mints a new key, so a retired key is never
	// brought back into service.
	statesWithTransitions := map[EncryptionKeyStateENUMType]map[EncryptionKeyStateENUMType]bool{
		EncryptionKeyStateActive: {
			EncryptionKeyStateActive:  true,
			EncryptionKeyStateRetired: true,
		},
		EncryptionKeyStateRetired: {
			EncryptionKeyStateRetired: true,
		},
	}

	availableNextStates, ok := statesWithTransitions[e.State]
	if !ok {
		return goutils.NewConsistencyError(
			fmt.Sprintf("encryption key can't transition out of state '%s'", e.State), nil, true,
		)
	}

	if _, ok := availableNextStates[newState]; !ok {
		return goutils.NewConsistencyError(
			fmt.Sprintf(
				"encryption key can't transition from '%s' to '%s'", e.State, newState,
			), nil, true,
		)
	}

	return nil
}
