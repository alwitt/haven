package models

import "time"

// Record a key-value record
type Record struct {
	// ID record ID
	ID string `json:"id" gorm:"column:id;primaryKey;unique" validate:"required,uuid_rfc4122"`

	// Name record name / key
	Name string `json:"name" gorm:"column:name;not null;unique" validate:"required"`

	// CreatedAt entry creation timestamp
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt entry update timestamp
	UpdatedAt time.Time `json:"updated_at"`
}

// RecordVersion one version of the record value
type RecordVersion struct {
	// ID record version ID
	ID string `json:"id" gorm:"column:id;primaryKey;unique" validate:"required"`

	// RecordID the parent record
	RecordID string `json:"record_id" gorm:"column:record_id;not null;" validate:"required,uuid_rfc4122"`

	// EncKeyID the symmetric encryption key which encrypted this record
	EncKeyID string `json:"enc_key_id" gorm:"column:enc_key_id;not null;" validate:"required,uuid_rfc4122"`

	// EncValue the symmetrically encrypted record value
	EncValue []byte `json:"enc_value" gorm:"column:enc_value;not null;" validate:"required"`
	// EncNonce the encryption nonce used
	EncNonce []byte `json:"enc_nonce" gorm:"column:enc_nonce;not null;" validate:"required"`

	// CreatedAt entry creation timestamp
	CreatedAt time.Time `json:"created_at"`
	// UpdatedAt entry update timestamp
	UpdatedAt time.Time `json:"updated_at"`
}
