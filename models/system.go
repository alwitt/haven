package models

import (
	"fmt"
	"time"
)

// SystemStateENUMType system operating state ENUM
type SystemStateENUMType string

const (
	// SystemStatePreInit first time system start
	SystemStatePreInit SystemStateENUMType = "PRE_INITIALIZATION"
	// SystemStateInit system perform first time initialization
	SystemStateInit SystemStateENUMType = "INITIALIZING"
	// SystemStateRunning system running normally
	SystemStateRunning SystemStateENUMType = "RUNNING"
)

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
			SystemStateInit:    true,
		},
		SystemStateInit: {
			SystemStateInit:    true,
			SystemStateRunning: true,
		},
		SystemStateRunning: {
			SystemStateRunning: true,
		},
	}

	availableNextStates, ok := statesWithTransitions[p.State]
	if !ok {
		return fmt.Errorf("email can't transition out of state '%s'", p.State)
	}

	if _, ok := availableNextStates[newState]; !ok {
		return fmt.Errorf("email can't transition from '%s' to '%s'", p.State, newState)
	}

	return nil
}
