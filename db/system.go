package db

import (
	"context"
	"fmt"

	"github.com/alwitt/haven/models"
)

// GlobalSystemParamEntryID ID of the singleton system parameter entry
const GlobalSystemParamEntryID = "system-parameters"

// getSystemParamEntry fetch the system param entry
//
// If the entry does not exist, initialize a new one.
func (d *databaseImpl) getSystemParamEntry() (systemParamsEntry, error) {
	var entries []systemParamsEntry
	dbErr := d.db.Where("id = ?", GlobalSystemParamEntryID).Find(&entries).Error
	if dbErr != nil {
		return systemParamsEntry{}, fmt.Errorf("failed to read system params table [%w]", dbErr)
	}
	if len(entries) == 0 {
		// Make a new one
		newEntry := systemParamsEntry{
			SystemParams: models.SystemParams{
				ID:    GlobalSystemParamEntryID,
				State: models.SystemStatePreInit,
			},
		}
		if dbErr = d.db.Create(&newEntry).Error; dbErr != nil {
			return systemParamsEntry{}, fmt.Errorf(
				"failed to setup singleton system params table [%w]", dbErr,
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
		return entry.SystemParams, fmt.Errorf("unable to fetch system parameter entry [%w]", err)
	}
	return entry.SystemParams, nil
}

// updateSystemParamState update the system parameter entry with new state
func (d *databaseImpl) updateSystemParamState(newState models.SystemStateENUMType) error {
	entry, err := d.getSystemParamEntry()
	if err != nil {
		return fmt.Errorf("unable to fetch system parameter entry [%w]", err)
	}

	if entry.State == newState {
		// NOOP
		return nil
	}

	if err := entry.ValidateNextState(newState); err != nil {
		return fmt.Errorf("system state change to %s not allowed [%w]", newState, err)
	}

	oldState := entry.State
	entry.State = newState
	if tmp := d.db.Updates(&entry); tmp.Error != nil {
		return fmt.Errorf("system state change update failed [%w]", err)
	}

	// record this event
	switch newState {
	case models.SystemStateInit:
		_, err = d.defineNewSystemEvent(models.SystemEventTypeInitializing, nil)
		if err != nil {
			return fmt.Errorf("failed to log system state change audit event [%w]", err)
		}

	case models.SystemStateRunning:
		if oldState == models.SystemStateInit {
			_, err = d.defineNewSystemEvent(models.SystemEventTypeInitialized, nil)
			if err != nil {
				return fmt.Errorf("failed to log system state change audit event [%w]", err)
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
