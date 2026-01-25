package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"gorm.io/datatypes"
)

// SystemEventTypeENUMType system event type ENUM value type
type SystemEventTypeENUMType string

const (
	// SystemEventTypeInitializing system is being initialized
	SystemEventTypeInitializing SystemEventTypeENUMType = "SYSTEM_INITIALIZING"

	// SystemEventTypeInitialized system is initialized
	SystemEventTypeInitialized SystemEventTypeENUMType = "SYSTEM_INITIALIZED"

	// SystemEventTypeNewEncryptionKey new encryption key is being added
	SystemEventTypeNewEncryptionKey SystemEventTypeENUMType = "ADD_NEW_ENCRYPTION_KEY"

	// SystemEventTypeActivateEncryptionKey encryption key is being activated
	SystemEventTypeActivateEncryptionKey SystemEventTypeENUMType = "ACTIVATE_ENCRYPTION_KEY"

	// SystemEventTypeDeactivateEncryptionKey encryption key is being deactivated
	SystemEventTypeDeactivateEncryptionKey SystemEventTypeENUMType = "DEACTIVATE_ENCRYPTION_KEY"

	// SystemEventTypeDeleteEncryptionKey encryption key is deleted
	SystemEventTypeDeleteEncryptionKey SystemEventTypeENUMType = "DELETE_ENCRYPTION_KEY"

	// SystemEventTypeAddNewRecord new data record is being added
	SystemEventTypeAddNewRecord SystemEventTypeENUMType = "ADD_NEW_RECORD"

	// SystemEventTypeDeleteRecord data record is deleted
	SystemEventTypeDeleteRecord SystemEventTypeENUMType = "DELETE_RECORD"
)

// SystemEventAudit recording of events occurring at the system level
type SystemEventAudit struct {
	// ID audit entry ID
	ID string `json:"id" gorm:"column:id;primaryKey;unique" validate:"required"`
	// EventType system event type
	EventType SystemEventTypeENUMType `json:"type" gorm:"column:type;not null" validate:"required,system_event_type"`
	// Metadata a metadata relating to the event
	Metadata datatypes.JSON `json:"metadata,omitempty" gorm:"column:metadata;default:null"`
	// CreatedAt entry creation timestamp
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt entry update timestamp
	UpdatedAt time.Time `json:"updated_at"`
}

// ParseMetadata parse the metadata based on the event type
func (a SystemEventAudit) ParseMetadata(validator *validator.Validate) (interface{}, error) {
	switch a.EventType {
	// Encryption key related system audit events
	case SystemEventTypeNewEncryptionKey:
		fallthrough
	case SystemEventTypeActivateEncryptionKey:
		fallthrough
	case SystemEventTypeDeactivateEncryptionKey:
		fallthrough
	case SystemEventTypeDeleteEncryptionKey:
		var parsed SystemEventEncKeyRelated
		if err := json.Unmarshal(a.Metadata, &parsed); err != nil {
			return nil, fmt.Errorf("system event '%s' metadata parse failed [%w]", a.EventType, err)
		}
		return parsed, validator.Struct(&parsed)

	// Data record related system audit events
	case SystemEventTypeAddNewRecord:
		fallthrough
	case SystemEventTypeDeleteRecord:
		var parsed SystemEventDataRecordRelated
		if err := json.Unmarshal(a.Metadata, &parsed); err != nil {
			return nil, fmt.Errorf("system event '%s' metadata parse failed [%w]", a.EventType, err)
		}
		return parsed, validator.Struct(&parsed)
	}
	return nil, nil
}

// SystemEventEncKeyRelated system event metadata related to encryption key
type SystemEventEncKeyRelated struct {
	// KeyID the encryption key added
	KeyID string `json:"key_id" validate:"required,uuid_rfc4122"`
}

// SystemEventDataRecordRelated system event metadata related to data record
type SystemEventDataRecordRelated struct {
	// RecordID the data record ID
	RecordID string `json:"record_id" validate:"required,uuid_rfc4122"`
	// RecordName the data record name
	RecordName string `json:"record_name" validate:"required"`
}
