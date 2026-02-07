package db

import (
	"context"

	"github.com/alwitt/haven/models"
	"gorm.io/gorm"
)

// --------------------------------------------------------------------------------------
// System audit events

// SystemEventAuditDBEntry system audit event DB entry
type SystemEventAuditDBEntry struct {
	models.SystemEventAudit
}

// TableName hard code table name
func (SystemEventAuditDBEntry) TableName() string {
	return "system_audit_events"
}

// --------------------------------------------------------------------------------------
// System parameters

// SystemParamsDBEntry system operating parameters DB entry
type SystemParamsDBEntry struct {
	models.SystemParams
}

// TableName hard code table name
func (SystemParamsDBEntry) TableName() string {
	return "system_params"
}

// --------------------------------------------------------------------------------------
// Encryption keys

// EncryptionKeyDBEntry encryption key DB entry
type EncryptionKeyDBEntry struct {
	models.EncryptionKey
}

// TableName hard code table name
func (EncryptionKeyDBEntry) TableName() string {
	return "encryption_keys"
}

// --------------------------------------------------------------------------------------
// Records

// RecordDBEntry key-value record DB entry
type RecordDBEntry struct {
	models.Record
}

// TableName hard code table name
func (RecordDBEntry) TableName() string {
	return "records"
}

// RecordVersionDBEntry record value DB entry
type RecordVersionDBEntry struct {
	models.RecordVersion
	Record RecordDBEntry        `gorm:"constraint:OnDelete:CASCADE;foreignKey:RecordID" validate:"-"`
	EncKey EncryptionKeyDBEntry `gorm:"constraint:OnDelete:CASCADE;foreignKey:EncKeyID" validate:"-"`
}

// TableName hard code table name
func (RecordVersionDBEntry) TableName() string {
	return "record_versions"
}

// --------------------------------------------------------------------------------------
// Utility

// DefineTables helper function meant to be used for unit-testing to prepare a
// database with tables
func DefineTables(_ context.Context, db *gorm.DB) error {
	return db.AutoMigrate(
		SystemEventAuditDBEntry{},
		SystemParamsDBEntry{},
		EncryptionKeyDBEntry{},
		RecordDBEntry{},
		RecordVersionDBEntry{},
	)
}
