package db

import (
	"context"
	"fmt"
	"time"

	"github.com/alwitt/goutils"
	"github.com/alwitt/haven/models"
)

// GlobalSystemParamEntryID ID of the singleton system parameter entry
const GlobalSystemParamEntryID = "system-parameters"

// getSystemParamEntry fetch the system param entry
//
// If the entry does not exist, initialize a new one.
func (d *databaseImpl) getSystemParamEntry() (SystemParamsDBEntry, error) {
	var entries []SystemParamsDBEntry
	dbErr := d.db.Where("id = ?", GlobalSystemParamEntryID).Find(&entries).Error
	if dbErr != nil {
		return SystemParamsDBEntry{}, goutils.NewSQLError(
			"failed to read system params table", dbErr, true,
		)
	}
	if len(entries) == 0 {
		// Make a new one
		newEntry := SystemParamsDBEntry{
			SystemParams: models.SystemParams{
				ID:    GlobalSystemParamEntryID,
				State: models.SystemStatePreInit,
			},
		}
		if dbErr = d.db.Create(&newEntry).Error; dbErr != nil {
			return SystemParamsDBEntry{}, goutils.NewSQLError(
				"failed to setup singleton system params table", dbErr, true,
			)
		}
		return newEntry, nil
	}
	return entries[0], nil
}

/*
GetSystemParamEntry fetch the global singleton system parameter entry

	@param ctx context.Context - execution context
	@returns the entry
*/
func (d *databaseImpl) GetSystemParamEntry(_ context.Context) (models.SystemParams, error) {
	entry, err := d.getSystemParamEntry()
	if err != nil {
		return entry.SystemParams, goutils.NewRuntimeError(
			"unable to fetch system parameter entry", err, true,
		)
	}
	return entry.SystemParams, nil
}

// stateChangeAuditEvent select the audit event recording a particular state transition.
//
// The second return value reports whether the transition is worth recording.
func stateChangeAuditEvent(
	oldState, newState models.SystemStateENUMType,
) (models.SystemEventTypeENUMType, bool) {
	switch {
	case oldState == models.SystemStatePreInit && newState == models.SystemStateReady:
		return models.SystemEventTypeInitialized, true
	case newState == models.SystemStateDEKRotating:
		return models.SystemEventTypeDEKRotationStarted, true
	case oldState == models.SystemStateDEKRotating && newState == models.SystemStateReady:
		return models.SystemEventTypeDEKRotationCompleted, true
	case newState == models.SystemStateKEKRotating:
		return models.SystemEventTypeKEKRotationStarted, true
	case oldState == models.SystemStateKEKRotating && newState == models.SystemStateReady:
		return models.SystemEventTypeKEKRotationCompleted, true
	}
	return "", false
}

// updateSystemParamState update the system parameter entry with new state
//
// The write is conditional on the entry still holding the state this call read, so a
// concurrent transition is reported rather than overwritten.
func (d *databaseImpl) updateSystemParamState(newState models.SystemStateENUMType) error {
	entry, err := d.getSystemParamEntry()
	if err != nil {
		return goutils.NewRuntimeError("unable to fetch system parameter entry", err, true)
	}

	if entry.State == newState {
		// NOOP
		return nil
	}

	if err := entry.ValidateNextState(newState); err != nil {
		return err
	}

	oldState := entry.State
	tmp := d.db.
		Model(&SystemParamsDBEntry{}).
		Where("id = ? AND state = ?", GlobalSystemParamEntryID, oldState).
		Updates(map[string]interface{}{"state": newState, "updated_at": time.Now().UTC()})
	if tmp.Error != nil {
		return goutils.NewSQLError("system state change update failed", tmp.Error, true)
	}
	if tmp.RowsAffected == 0 {
		return goutils.NewConsistencyError(
			fmt.Sprintf(
				"system is no longer in state '%s'; can't transition to '%s'", oldState, newState,
			),
			nil, true,
		)
	}

	// record this event
	if eventType, record := stateChangeAuditEvent(oldState, newState); record {
		if _, err := d.defineNewSystemEvent(eventType, nil); err != nil {
			return goutils.NewRuntimeError(
				"failed to log system state change audit event", err, true,
			)
		}
	}

	return nil
}

/*
MarkSystemReady mark the system ready for normal operation

	@param ctx context.Context - execution context
*/
func (d *databaseImpl) MarkSystemReady(_ context.Context) error {
	return d.updateSystemParamState(models.SystemStateReady)
}

/*
MarkSystemRotatingDEK mark an encryption key rotation in progress

	@param ctx context.Context - execution context
*/
func (d *databaseImpl) MarkSystemRotatingDEK(_ context.Context) error {
	return d.updateSystemParamState(models.SystemStateDEKRotating)
}

/*
MarkSystemRotatingKEK mark a primary RSA key pair rotation in progress

	@param ctx context.Context - execution context
*/
func (d *databaseImpl) MarkSystemRotatingKEK(_ context.Context) error {
	return d.updateSystemParamState(models.SystemStateKEKRotating)
}
