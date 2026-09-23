package maintenance_test

import (
	"context"
	"testing"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/stretchr/testify/assert"
)

// newKEKFixture the key pair a rotation moves to
func newKEKFixture(t *testing.T) encryption.KEKParams {
	return encryption.KEKParams{
		CertFile: certFixture(t, "user-root.crt"), KeyFile: certFixture(t, "user-root.key"),
	}
}

// TestMaintenanceRotateKEK verifies a complete primary RSA key pair rotation: the keys are
// re-wrapped, the record versions are not touched at all, and a runner holding the new key
// pair reads the data.
func TestMaintenanceRotateKEK(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newTestFixture(utCtx, t, "self-signed", 0)
	assert.Nil(fixture.uut.Initialize(utCtx))

	values := map[string][]byte{
		"alpha": []byte("one"), "bravo": []byte("two"), "charlie": []byte("three"),
	}
	fixture.writeValues(utCtx, t, values)

	originalKey := fixture.encryptionKeys(utCtx, t)[0]
	assert.Equal(fixture.engine.KEKID(), originalKey.KekID)

	// The cipher text of every version, as it stands before the rotation
	before := map[string]models.RecordVersion{}
	for _, version := range fixture.recordVersions(utCtx, t) {
		before[version.ID] = version
	}

	assert.Nil(fixture.uut.RotateKEK(utCtx, newKEKFixture(t)))
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))

	// The encryption key keeps its ID and its state, and only its wrapping changed
	keys := fixture.encryptionKeys(utCtx, t)
	assert.Len(keys, 1)
	assert.Equal(originalKey.ID, keys[0].ID)
	assert.Equal(models.EncryptionKeyStateActive, keys[0].State)
	assert.NotEqual(originalKey.KekID, keys[0].KekID)
	assert.NotEqual(originalKey.EncKeyMaterial, keys[0].EncKeyMaterial)

	// Not one byte of record data moved. This is the whole payoff of envelope encryption:
	// the associated data binds the encryption key's ID, not its wrapping.
	after := fixture.recordVersions(utCtx, t)
	assert.Len(after, len(before))
	for _, version := range after {
		original, ok := before[version.ID]
		assert.True(ok)
		assert.Equal(original.EncValue, version.EncValue)
		assert.Equal(original.EncNonce, version.EncNonce)
		assert.Equal(original.EncKeyID, version.EncKeyID)
	}

	// A process restarted with the new key pair unwraps the key and reads the data. The
	// original fixture's engine could still serve this from cache, so it proves nothing.
	restarted := newTestFixtureOn(utCtx, t, fixture.persistence, "user-root", 0)
	assert.Equal(keys[0].KekID, restarted.engine.KEKID())
	restarted.assertValuesReadable(utCtx, t, values)

	assert.Equal(
		[]models.SystemEventTypeENUMType{
			models.SystemEventTypeKEKRotationStarted,
			models.SystemEventTypeKEKRotationCompleted,
		},
		fixture.auditEventTypes(utCtx, t)[len(fixture.auditEventTypes(utCtx, t))-2:],
	)
}

// TestMaintenanceRotateKEKRejects verifies that a key pair which cannot be used is refused
// before the system state moves.
func TestMaintenanceRotateKEKRejects(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newTestFixture(utCtx, t, "self-signed", 0)
	assert.Nil(fixture.uut.Initialize(utCtx))

	// A key pair which will not load
	assert.Error(fixture.uut.RotateKEK(utCtx, encryption.KEKParams{
		CertFile: certFixture(t, "user-expired.crt"), KeyFile: certFixture(t, "user-expired.key"),
	}))
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))

	// The key pair already in use has nothing to rotate to
	assert.Error(fixture.uut.RotateKEK(utCtx, encryption.KEKParams{
		CertFile: certFixture(t, "self-signed.crt"), KeyFile: certFixture(t, "self-signed.key"),
	}))
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))

	// Neither attempt touched the encryption key
	keys := fixture.encryptionKeys(utCtx, t)
	assert.Len(keys, 1)
	assert.Equal(fixture.engine.KEKID(), keys[0].KekID)
}

// TestMaintenanceRotateKEKResume verifies that a rotation interrupted after the barrier
// reruns to completion.
func TestMaintenanceRotateKEKResume(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newTestFixture(utCtx, t, "self-signed", 0)
	assert.Nil(fixture.uut.Initialize(utCtx))

	values := map[string][]byte{"alpha": []byte("one"), "bravo": []byte("two")}
	fixture.writeValues(utCtx, t, values)

	// Stage a crash after the barrier committed but before anything was re-wrapped
	assert.Nil(fixture.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			return dbClient.MarkSystemRotatingKEK(ctx)
		},
	))

	assert.Nil(fixture.uut.RotateKEK(utCtx, newKEKFixture(t)))
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))

	restarted := newTestFixtureOn(utCtx, t, fixture.persistence, "user-root", 0)
	assert.Equal(fixture.encryptionKeys(utCtx, t)[0].KekID, restarted.engine.KEKID())
	restarted.assertValuesReadable(utCtx, t, values)

	// Rerunning a completed rotation with the same key pair is refused: by then it is the
	// pair in use, and there is nothing left to move
	assert.Error(restarted.uut.RotateKEK(utCtx, newKEKFixture(t)))
	assert.Equal(models.SystemStateReady, restarted.systemState(utCtx, t))
}

// TestMaintenanceRotateKEKResumePartial verifies that a rotation interrupted with the keys
// already re-wrapped still closes, rather than failing to unwrap what it already converted.
func TestMaintenanceRotateKEKResumePartial(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	fixture := newTestFixture(utCtx, t, "self-signed", 0)
	assert.Nil(fixture.uut.Initialize(utCtx))

	values := map[string][]byte{"alpha": []byte("one")}
	fixture.writeValues(utCtx, t, values)

	newKEK, err := fixture.engine.LoadKEK(utCtx, newKEKFixture(t))
	assert.Nil(err)

	// Stage a crash after the keys were re-wrapped but before the closing transition
	assert.Nil(fixture.persistence.UseDatabaseInTransaction(
		utCtx, func(ctx context.Context, dbClient db.Database) error {
			if err := dbClient.MarkSystemRotatingKEK(ctx); err != nil {
				return err
			}
			keys, err := dbClient.ListEncryptionKeys(ctx, db.EncryptionKeyQueryFilter{})
			if err != nil {
				return err
			}
			return fixture.engine.RewrapEncryptionKeys(ctx, keys, newKEK, dbClient)
		},
	))

	// This is what a half-finished rotation looks like from outside: the keys carry a key
	// pair the runner does not hold, and the count is what tells an operator how much of the
	// rotation already happened
	status, err := fixture.uut.Status(utCtx)
	assert.Nil(err)
	assert.Equal(models.SystemStateKEKRotating, status.State)
	assert.Equal(1, status.KeysUnderAnotherKEK)
	assert.Equal(fixture.engine.KEKID(), status.KEKID)

	// The rerun skips the keys already carrying the new pair's ID rather than trying to
	// unwrap them with the old private key
	assert.Nil(fixture.uut.RotateKEK(utCtx, newKEKFixture(t)))
	assert.Equal(models.SystemStateReady, fixture.systemState(utCtx, t))

	restarted := newTestFixtureOn(utCtx, t, fixture.persistence, "user-root", 0)
	restarted.assertValuesReadable(utCtx, t, values)
}
