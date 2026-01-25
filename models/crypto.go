// Package models - system data models
package models

import (
	"fmt"
	"time"
)

// EncryptionKeyStateENUMType encryption state enum type
type EncryptionKeyStateENUMType string

const (
	// EncryptionKeyStateActive the encryption key is active
	EncryptionKeyStateActive EncryptionKeyStateENUMType = "ACTIVE"
	// EncryptionKeyStateInactive the encryption key is inactive
	EncryptionKeyStateInactive EncryptionKeyStateENUMType = "INACTIVE"
)

// EncryptionKey an encryption key used to encrypt record value
//
// These encryption keys are meant to be used for symmetric encryption
type EncryptionKey struct {
	// ID key ID
	ID string `json:"id" gorm:"column:id;primaryKey;unique" validate:"required,uuid_rfc4122"`

	// EncKeyMaterial the encrypted encryption key material
	EncKeyMaterial []byte `json:"enc_key_material" gorm:"column:enc_key_material;not null" validate:"required"`

	// State the encryption key state
	State EncryptionKeyStateENUMType `json:"state" gorm:"column:state;not null" validate:"required,enc_key_state"`

	// CreatedAt entry creation timestamp
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt entry update timestamp
	UpdatedAt time.Time `json:"updated_at"`
}

// ValidateNextState verify can transition to new state
func (e *EncryptionKey) ValidateNextState(newState EncryptionKeyStateENUMType) error {
	statesWithTransitions := map[EncryptionKeyStateENUMType]map[EncryptionKeyStateENUMType]bool{
		EncryptionKeyStateActive: {
			EncryptionKeyStateActive:   true,
			EncryptionKeyStateInactive: true,
		},
		EncryptionKeyStateInactive: {
			EncryptionKeyStateInactive: true,
			EncryptionKeyStateActive:   true,
		},
	}

	availableNextStates, ok := statesWithTransitions[e.State]
	if !ok {
		return fmt.Errorf("email can't transition out of state '%s'", e.State)
	}

	if _, ok := availableNextStates[newState]; !ok {
		return fmt.Errorf("email can't transition from '%s' to '%s'", e.State, newState)
	}

	return nil
}
