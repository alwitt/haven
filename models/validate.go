package models

import (
	"github.com/alwitt/goutils"
	"github.com/go-playground/validator/v10"
)

/*
RegisterWithValidator register with the validator this custom validation support

	@param v *validator.Validate - the validator to register against
	@return whether successful
*/
func RegisterWithValidator(v *validator.Validate) error {
	if err := goutils.RegisterENUMInValidator(
		v, "enc_key_state", goutils.ValidateStringENUM[EncryptionKeyStateENUMType](),
	); err != nil {
		return err
	}

	if err := goutils.RegisterENUMInValidator(
		v, "system_state", goutils.ValidateStringENUM[SystemStateENUMType](),
	); err != nil {
		return err
	}

	if err := goutils.RegisterENUMInValidator(
		v, "system_event_type", goutils.ValidateStringENUM[SystemEventTypeENUMType](),
	); err != nil {
		return err
	}

	return nil
}
