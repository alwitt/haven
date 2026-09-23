package models

import "github.com/alwitt/goutils"

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

// MaintenanceError encountered when running a maintenance action
type MaintenanceError struct{ goutils.BaseError }

// NewMaintenanceError builds a MaintenanceError, optionally capturing the call stack.
func NewMaintenanceError(message string, core error, getCallStack bool) MaintenanceError {
	base := goutils.BaseError{Name: "MaintenanceError", Message: message, Core: core}
	if getCallStack {
		base.Stack = goutils.GetCallStack(1)
	}
	return MaintenanceError{BaseError: base}
}
