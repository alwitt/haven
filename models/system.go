package models

import (
	"fmt"
	"time"

	"github.com/alwitt/goutils"
)

// SystemStateENUMType system operating state ENUM
type SystemStateENUMType string

const (
	// SystemStatePreInit no encryption key exists yet; the system has never been initialized
	SystemStatePreInit SystemStateENUMType = "PRE_INITIALIZATION"
	// SystemStateReady exactly one active encryption key; normal operation
	SystemStateReady SystemStateENUMType = "READY"
	// SystemStateDEKRotating an encryption key rotation is underway or was interrupted
	SystemStateDEKRotating SystemStateENUMType = "DEK_ROTATION_IN_PROGRESS"
	// SystemStateKEKRotating a primary RSA key pair rotation is underway or was interrupted
	SystemStateKEKRotating SystemStateENUMType = "KEK_ROTATION_IN_PROGRESS"
)

// Values all valid SystemStateENUMType values
func (SystemStateENUMType) Values() []SystemStateENUMType {
	return []SystemStateENUMType{
		SystemStatePreInit,
		SystemStateReady,
		SystemStateDEKRotating,
		SystemStateKEKRotating,
	}
}

// SystemParams system operating parameters
type SystemParams struct {
	// ID param entry ID. It must always be system-parameters
	ID string `json:"id" gorm:"column:id;primaryKey;unique" validate:"required,oneof=system-parameters"`

	// State system operating state
	State SystemStateENUMType `json:"state" gorm:"column:state;not null" validate:"required,system_state"`

	// CreatedAt entry creation timestamp
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt entry update timestamp
	UpdatedAt time.Time `json:"updated_at"`
}

// ValidateNextState verify can transition to new state
func (p *SystemParams) ValidateNextState(newState SystemStateENUMType) error {
	statesWithTransitions := map[SystemStateENUMType]map[SystemStateENUMType]bool{
		SystemStatePreInit: {
			SystemStatePreInit: true,
			SystemStateReady:   true,
		},
		SystemStateReady: {
			SystemStateReady:       true,
			SystemStateDEKRotating: true,
			SystemStateKEKRotating: true,
		},
		SystemStateDEKRotating: {
			SystemStateDEKRotating: true,
			SystemStateReady:       true,
		},
		SystemStateKEKRotating: {
			SystemStateKEKRotating: true,
			SystemStateReady:       true,
		},
	}

	availableNextStates, ok := statesWithTransitions[p.State]
	if !ok {
		return goutils.NewConsistencyError(
			fmt.Sprintf("system can't transition out of state '%s'", p.State), nil, true,
		)
	}

	if _, ok := availableNextStates[newState]; !ok {
		return goutils.NewConsistencyError(
			fmt.Sprintf(
				"system can't transition from '%s' to '%s'", p.State, newState,
			), nil, true,
		)
	}

	return nil
}
