package db

import (
	"context"

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
		return SystemParamsDBEntry{}, models.NewSQLError(
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
			return SystemParamsDBEntry{}, models.NewSQLError(
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

// updateSystemParamState update the system parameter entry with new state
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
	entry.State = newState
	if tmp := d.db.Updates(&entry); tmp.Error != nil {
		return models.NewSQLError("system state change update failed", tmp.Error, true)
	}

	// record this event
	switch newState {
	case models.SystemStateInit:
		_, err = d.defineNewSystemEvent(models.SystemEventTypeInitializing, nil)
		if err != nil {
			return goutils.NewRuntimeError(
				"failed to log system state change audit event", err, true,
			)
		}

	case models.SystemStateRunning:
		if oldState == models.SystemStateInit {
			_, err = d.defineNewSystemEvent(models.SystemEventTypeInitialized, nil)
			if err != nil {
				return goutils.NewRuntimeError(
					"failed to log system state change audit event", err, true,
				)
			}
		}
	}

	return nil
}

/*
MarkSystemInitializing mark system is initializing

	@param ctx context.Context - execution context
*/
func (d *databaseImpl) MarkSystemInitializing(_ context.Context) error {
	return d.updateSystemParamState(models.SystemStateInit)
}

/*
MarkSystemInitializing mark system fully initialized

	@param ctx context.Context - execution context
*/
func (d *databaseImpl) MarkSystemInitialized(_ context.Context) error {
	return d.updateSystemParamState(models.SystemStateRunning)
}
