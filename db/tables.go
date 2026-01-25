package db

import "github.com/alwitt/haven/models"

// --------------------------------------------------------------------------------------
// System audit events

type systemEventAuditEntry struct {
	models.SystemEventAudit
}

// TableName hard code table name
func (systemEventAuditEntry) TableName() string {
	return "system_audit_events"
}

// --------------------------------------------------------------------------------------
// System parameters

type systemParamsEntry struct {
	models.SystemParams
}

// TableName hard code table name
func (systemParamsEntry) TableName() string {
	return "system_params"
}

// --------------------------------------------------------------------------------------
// Encryption keys

// encryptionKeyEntry encryption key DB entry
type encryptionKeyEntry struct {
	models.EncryptionKey
}

// TableName hard code table name
func (encryptionKeyEntry) TableName() string {
	return "encryption_keys"
}

// --------------------------------------------------------------------------------------
// Records

// recordEntry key-value record DB entry
type recordEntry struct {
	models.Record
}

// TableName hard code table name
func (recordEntry) TableName() string {
	return "records"
}

// recordVersionEntry record value DB entry
type recordVersionEntry struct {
	models.RecordVersion
	Record recordEntry        `gorm:"constraint:OnDelete:CASCADE;foreignKey:RecordID" validate:"-"`
	EncKey encryptionKeyEntry `gorm:"constraint:OnDelete:CASCADE;foreignKey:EncKeyID" validate:"-"`
}

// TableName hard code table name
func (recordVersionEntry) TableName() string {
	return "record_versions"
}
