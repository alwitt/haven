package models_test

import (
	"testing"

	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	"github.com/stretchr/testify/assert"
)

func TestRecordVersionAssociatedData(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	base := models.RecordVersion{
		ID:       ulid.Make().String(),
		RecordID: uuid.NewString(),
		EncKeyID: uuid.NewString(),
	}

	// Deterministic, and independent of fields outside the binding
	assert.Equal(base.AssociatedData(), base.AssociatedData())
	{
		withPayload := base
		withPayload.EncValue = []byte(uuid.NewString())
		withPayload.EncNonce = []byte(uuid.NewString())
		assert.Equal(base.AssociatedData(), withPayload.AssociatedData())
	}

	// Any one bound field changing changes the output
	{
		other := base
		other.ID = ulid.Make().String()
		assert.NotEqual(base.AssociatedData(), other.AssociatedData())
	}
	{
		other := base
		other.RecordID = uuid.NewString()
		assert.NotEqual(base.AssociatedData(), other.AssociatedData())
	}
	{
		other := base
		other.EncKeyID = uuid.NewString()
		assert.NotEqual(base.AssociatedData(), other.AssociatedData())
	}
}
