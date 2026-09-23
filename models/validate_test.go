package models_test

import (
	"testing"

	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func TestENUMValues(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	assert.ElementsMatch(
		[]models.EncryptionKeyStateENUMType{
			models.EncryptionKeyStateActive,
			models.EncryptionKeyStateRetired,
		},
		models.EncryptionKeyStateENUMType("").Values(),
	)

	assert.ElementsMatch(
		[]models.SystemStateENUMType{
			models.SystemStatePreInit,
			models.SystemStateReady,
			models.SystemStateDEKRotating,
			models.SystemStateKEKRotating,
		},
		models.SystemStateENUMType("").Values(),
	)

	assert.ElementsMatch(
		[]models.SystemEventTypeENUMType{
			models.SystemEventTypeInitialized,
			models.SystemEventTypeDEKRotationStarted,
			models.SystemEventTypeDEKRotationCompleted,
			models.SystemEventTypeKEKRotationStarted,
			models.SystemEventTypeKEKRotationCompleted,
			models.SystemEventTypeNewEncryptionKey,
			models.SystemEventTypeRetireEncryptionKey,
			models.SystemEventTypeDeleteEncryptionKey,
			models.SystemEventTypeAddNewRecord,
			models.SystemEventTypeDeleteRecord,
			models.SystemEventTypePurgeRecordVersion,
		},
		models.SystemEventTypeENUMType("").Values(),
	)
}

func TestSystemStateTransitions(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	legal := map[models.SystemStateENUMType][]models.SystemStateENUMType{
		models.SystemStatePreInit:     {models.SystemStatePreInit, models.SystemStateReady},
		models.SystemStateReady:       {models.SystemStateReady, models.SystemStateDEKRotating, models.SystemStateKEKRotating},
		models.SystemStateDEKRotating: {models.SystemStateDEKRotating, models.SystemStateReady},
		models.SystemStateKEKRotating: {models.SystemStateKEKRotating, models.SystemStateReady},
	}

	for from, allowed := range legal {
		permitted := map[models.SystemStateENUMType]bool{}
		for _, to := range allowed {
			permitted[to] = true
		}
		for _, to := range models.SystemStateENUMType("").Values() {
			entry := models.SystemParams{ID: "system-parameters", State: from}
			err := entry.ValidateNextState(to)
			if permitted[to] {
				assert.Nilf(err, "%s -> %s should be legal", from, to)
			} else {
				assert.Errorf(err, "%s -> %s should be rejected", from, to)
			}
		}
	}

	// A rotation can't hand straight over to the other rotation
	dekRotating := models.SystemParams{ID: "system-parameters", State: models.SystemStateDEKRotating}
	assert.Error(dekRotating.ValidateNextState(models.SystemStateKEKRotating))

	// The system never returns to pre-initialization
	ready := models.SystemParams{ID: "system-parameters", State: models.SystemStateReady}
	assert.Error(ready.ValidateNextState(models.SystemStatePreInit))
}

func TestEncryptionKeyStateTransitions(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	active := models.EncryptionKey{State: models.EncryptionKeyStateActive}
	assert.Nil(active.ValidateNextState(models.EncryptionKeyStateActive))
	assert.Nil(active.ValidateNextState(models.EncryptionKeyStateRetired))

	// Retirement is one way: a rotation always mints a new key
	retired := models.EncryptionKey{State: models.EncryptionKeyStateRetired}
	assert.Nil(retired.ValidateNextState(models.EncryptionKeyStateRetired))
	assert.Error(retired.ValidateNextState(models.EncryptionKeyStateActive))
}

// TestEncryptionKeyStateCapabilities verifies what each encryption key state permits.
//
// A retired key is decrypt-only: that is the whole reason the state exists, since an
// encryption key rotation must read the data it is moving off the old key.
func TestEncryptionKeyStateCapabilities(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	assert.True(models.EncryptionKeyStateActive.CanEncrypt())
	assert.True(models.EncryptionKeyStateActive.CanDecrypt())

	assert.False(models.EncryptionKeyStateRetired.CanEncrypt())
	assert.True(models.EncryptionKeyStateRetired.CanDecrypt())

	// An unrecognized state permits nothing
	unknown := models.EncryptionKeyStateENUMType("NOT_A_STATE")
	assert.False(unknown.CanEncrypt())
	assert.False(unknown.CanDecrypt())
}

func TestENUMValidation(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	v := validator.New()
	assert.Nil(models.RegisterWithValidator(v))

	// Case 0: encryption key state
	{
		type probe struct {
			State models.EncryptionKeyStateENUMType `validate:"required,enc_key_state"`
		}
		for _, member := range models.EncryptionKeyStateENUMType("").Values() {
			assert.Nil(v.Struct(&probe{State: member}), "member %s", member)
		}
		assert.Error(v.Struct(&probe{State: "NOT_A_STATE"}))
		assert.Error(v.Struct(&probe{}))
	}

	// Case 1: system state
	{
		type probe struct {
			State models.SystemStateENUMType `validate:"required,system_state"`
		}
		for _, member := range models.SystemStateENUMType("").Values() {
			assert.Nil(v.Struct(&probe{State: member}), "member %s", member)
		}
		assert.Error(v.Struct(&probe{State: "NOT_A_STATE"}))
		assert.Error(v.Struct(&probe{}))
	}

	// Case 2: system event type
	{
		type probe struct {
			EventType models.SystemEventTypeENUMType `validate:"required,system_event_type"`
		}
		for _, member := range models.SystemEventTypeENUMType("").Values() {
			assert.Nil(v.Struct(&probe{EventType: member}), "member %s", member)
		}
		assert.Error(v.Struct(&probe{EventType: "NOT_AN_EVENT"}))
		assert.Error(v.Struct(&probe{}))
	}
}
