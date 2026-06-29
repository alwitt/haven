package models

import "github.com/alwitt/goutils"

// PersistenceError encountered when operating the persistence layer (e.g. SQL statement failed)
//
// Not recoverable
type PersistenceError struct{ goutils.BaseError }

// NewPersistenceError builds a PersistenceError, optionally capturing the call stack.
func NewPersistenceError(message string, core error, getCallStack bool) PersistenceError {
	base := goutils.BaseError{Name: "PersistenceError", Message: message, Core: core}
	if getCallStack {
		base.Stack = goutils.GetCallStack(1)
	}
	return PersistenceError{BaseError: base}
}

// SQLError wraps an error returned by the GORM layer, indicating a SQL statement failed
type SQLError struct{ goutils.BaseError }

// NewSQLError builds a SQLError, optionally capturing the call stack.
func NewSQLError(message string, core error, getCallStack bool) SQLError {
	base := goutils.BaseError{Name: "SQLError", Message: message, Core: core}
	if getCallStack {
		base.Stack = goutils.GetCallStack(1)
	}
	return SQLError{BaseError: base}
}

// KVStoreError encountered when operating the key-value store layer
type KVStoreError struct{ goutils.BaseError }

// NewKVStoreError builds a KVStoreError, optionally capturing the call stack.
func NewKVStoreError(message string, core error, getCallStack bool) KVStoreError {
	base := goutils.BaseError{Name: "KVStoreError", Message: message, Core: core}
	if getCallStack {
		base.Stack = goutils.GetCallStack(1)
	}
	return KVStoreError{BaseError: base}
}

// EncryptionError encountered when operating the cryptography engine layer
type EncryptionError struct{ goutils.BaseError }

// NewEncryptionError builds an EncryptionError, optionally capturing the call stack.
func NewEncryptionError(message string, core error, getCallStack bool) EncryptionError {
	base := goutils.BaseError{Name: "EncryptionError", Message: message, Core: core}
	if getCallStack {
		base.Stack = goutils.GetCallStack(1)
	}
	return EncryptionError{BaseError: base}
}
