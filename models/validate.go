package models

import (
	"reflect"

	"github.com/go-playground/validator/v10"
)

/*
RegisterWithValidator register with the validator this custom validation support

	@param v *validator.Validate - the validator to register against
	@return whether successful
*/
func RegisterWithValidator(v *validator.Validate) error {
	if err := v.RegisterValidation(
		"enc_key_state", validateEncKeyStateType,
	); err != nil {
		return err
	}

	if err := v.RegisterValidation(
		"system_state", validateSystemStateType,
	); err != nil {
		return err
	}

	if err := v.RegisterValidation(
		"system_event_type", validateSystemEventType,
	); err != nil {
		return err
	}

	return nil
}

func validateEncKeyStateType(fl validator.FieldLevel) bool {
	if fl.Field().Kind() != reflect.String {
		return false
	}
	switch EncryptionKeyStateENUMType(fl.Field().String()) {
	case EncryptionKeyStateActive:
		fallthrough
	case EncryptionKeyStateInactive:
		return true
	}
	return false
}

func validateSystemStateType(fl validator.FieldLevel) bool {
	if fl.Field().Kind() != reflect.String {
		return false
	}
	switch SystemStateENUMType(fl.Field().String()) {
	case SystemStatePreInit:
		fallthrough
	case SystemStateInit:
		fallthrough
	case SystemStateRunning:
		return true
	}
	return false
}

func validateSystemEventType(fl validator.FieldLevel) bool {
	if fl.Field().Kind() != reflect.String {
		return false
	}
	switch SystemEventTypeENUMType(fl.Field().String()) {
	case SystemEventTypeInitializing:
		fallthrough
	case SystemEventTypeInitialized:
		fallthrough
	case SystemEventTypeNewEncryptionKey:
		fallthrough
	case SystemEventTypeActivateEncryptionKey:
		fallthrough
	case SystemEventTypeDeactivateEncryptionKey:
		fallthrough
	case SystemEventTypeDeleteEncryptionKey:
		fallthrough
	case SystemEventTypeAddNewRecord:
		fallthrough
	case SystemEventTypeDeleteRecord:
		return true
	}
	return false
}
