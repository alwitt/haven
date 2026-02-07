// Package db - persistence layer
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/alwitt/haven/models"
	"github.com/oklog/ulid/v2"
	"gorm.io/datatypes"
)

// defineNewSystemEvent record a new system event
func (d *databaseImpl) defineNewSystemEvent(
	eventType models.SystemEventTypeENUMType, metadata interface{},
) (models.SystemEventAudit, error) {

	newEntry := SystemEventAuditDBEntry{
		SystemEventAudit: models.SystemEventAudit{ID: ulid.Make().String(), EventType: eventType},
	}

	if metadata != nil {
		if err := d.validator.Struct(metadata); err != nil {
			return models.SystemEventAudit{}, fmt.Errorf(
				"new system event '%s' metadata entry is not valid [%w]", eventType, err,
			)
		}

		metadataStr, _ := json.Marshal(&metadata)
		newEntry.Metadata = datatypes.JSON(metadataStr)
	}

	if err := d.validator.Struct(&newEntry); err != nil {
		return models.SystemEventAudit{}, fmt.Errorf(
			"new system event '%s' entry is not valid [%w]", eventType, err,
		)
	}

	if tmp := d.db.Create(&newEntry); tmp.Error != nil {
		return models.SystemEventAudit{}, fmt.Errorf(
			"new system event '%s' insert failed [%w]", eventType, tmp.Error,
		)
	}

	return newEntry.SystemEventAudit, nil
}

/*
ListSystemEvents list captured system events

	@param ctx context.Context - execution context
	@param filters SystemEventQueryFilter - entry listing filter
	@return list of system events
*/
func (d *databaseImpl) ListSystemEvents(
	_ context.Context, filters SystemEventQueryFilter,
) ([]models.SystemEventAudit, error) {
	query := d.db.Model(&SystemEventAuditDBEntry{})

	if len(filters.EventTypes) > 0 {
		query = query.Where("type in ?", filters.EventTypes)
	}

	if filters.EventsAfter != nil {
		query = query.Where("created_at >= ?", *filters.EventsAfter)
	}
	if filters.EventsBefore != nil {
		query = query.Where("created_at <= ?", *filters.EventsBefore)
	}

	if filters.Limit != nil {
		query = query.Limit(*filters.Limit)
	}
	if filters.Offset != nil {
		query = query.Offset(*filters.Offset)
	}

	query = query.Order("created_at")

	var entries []SystemEventAuditDBEntry
	if tmp := query.Find(&entries); tmp.Error != nil {
		return nil, fmt.Errorf("failed to list captured system events [%w]", tmp.Error)
	}

	result := []models.SystemEventAudit{}
	for _, entry := range entries {
		result = append(result, entry.SystemEventAudit)
	}

	return result, nil
}
