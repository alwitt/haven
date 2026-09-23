package encryption_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/alwitt/haven/db"
	"github.com/alwitt/haven/encryption"
	mockdb "github.com/alwitt/haven/mocks/db"
	"github.com/alwitt/haven/models"
	"github.com/apex/log"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// testCertFixture absolute path of a certificate fixture
func testCertFixture(t *testing.T, name string) string {
	path, err := filepath.Abs(filepath.Join("../test/certs", name))
	assert.New(t).Nil(err)
	return path
}

// newTestEngine prepare a cryptography engine against a key pair fixture, holding its keys
// for the duration of the test
func newTestEngine(
	utCtx context.Context, t *testing.T, certName, keyName string, persistence db.Client,
) encryption.CryptographyEngine {
	uut, err := encryption.NewCryptographyEngine(utCtx, encryption.CryptographyEngineParams{
		Persistence:        persistence,
		PrimaryRSACertFile: testCertFixture(t, certName),
		PrimaryRSAKeyFile:  testCertFixture(t, keyName),
		KeyCacheTTL:        time.Hour,
	})
	assert.New(t).Nil(err)
	return uut
}

// mintTestKey have the engine mint a key, capturing the wrapped key material the way
// persistence would have stored it
func mintTestKey(
	utCtx context.Context,
	t *testing.T,
	uut encryption.CryptographyEngine,
	mockDatabase *mockdb.Database,
	entry *models.EncryptionKey,
) {
	assert := assert.New(t)

	mockDatabase.On(
		"RecordEncryptionKey",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.AnythingOfType("[]uint8"),
		mock.AnythingOfType("string"),
	).Run(func(args mock.Arguments) {
		material, ok := args.Get(1).([]byte)
		assert.True(ok)
		entry.EncKeyMaterial = material
	}).Return(func(_ context.Context, material []byte, kekID string) models.EncryptionKey {
		entry.EncKeyMaterial = material
		entry.KekID = kekID
		return *entry
	}, nil).Once()

	minted, err := uut.NewEncryptionKey(utCtx, mockDatabase)
	assert.Nil(err)
	assert.Equal(entry.ID, minted.ID)
}

// sealTestVersion build a record version holding the given plain text, sealed under a key
func sealTestVersion(
	utCtx context.Context,
	t *testing.T,
	uut encryption.CryptographyEngine,
	mockDatabase *mockdb.Database,
	encKey models.EncryptionKey,
	plainText []byte,
) models.RecordVersion {
	assert := assert.New(t)

	version := models.RecordVersion{
		ID: db.NewRecordVersionID(), RecordID: uuid.NewString(), EncKeyID: encKey.ID,
	}

	_, encrypted, err := uut.EncryptData(
		utCtx, encKey.ID, plainText, version.AssociatedData(), mockDatabase,
	)
	assert.Nil(err)

	version.EncValue = encrypted.CipherText
	version.EncNonce = encrypted.Nonce
	return version
}

// TestCryptoEngineReEncryptRecordVersions verifies that a version moved onto a new
// encryption key is re-sealed with its associated data recomputed from the new key ID.
//
// The associated data is part of the on-disk format, so a version re-sealed with the
// associated data of the row it came from is unreadable forever. Decrypting the result
// under both the new and the old associated data is the only thing which catches that.
func TestCryptoEngineReEncryptRecordVersions(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)

	uut := newTestEngine(utCtx, t, "self-signed.crt", "self-signed.key", mockDBClient)

	// The key the data starts on, and the key it is moving to
	oldKey := models.EncryptionKey{ID: uuid.NewString(), State: models.EncryptionKeyStateActive}
	mintTestKey(utCtx, t, uut, mockDatabase, &oldKey)

	plainTexts := [][]byte{[]byte("first secret"), []byte("second secret")}
	versions := []models.RecordVersion{}
	for _, plainText := range plainTexts {
		versions = append(versions, sealTestVersion(utCtx, t, uut, mockDatabase, oldKey, plainText))
	}

	newKey := models.EncryptionKey{ID: uuid.NewString(), State: models.EncryptionKeyStateActive}
	mintTestKey(utCtx, t, uut, mockDatabase, &newKey)

	// A maintenance action retires the old key through persistence; the engine sees the new
	// state on its next listing
	retiredOldKey := oldKey
	retiredOldKey.State = models.EncryptionKeyStateRetired
	mockDatabase.On(
		"ListEncryptionKeys",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.AnythingOfType("db.EncryptionKeyQueryFilter"),
	).Return([]models.EncryptionKey{retiredOldKey, newKey}, nil).Once()
	_, err := uut.ListEncryptionKeys(utCtx, db.EncryptionKeyQueryFilter{}, mockDatabase)
	assert.Nil(err)

	// Capture what the drain writes back
	written := map[string]encryption.EncryptedData{}
	mockDatabase.On(
		"UpdateRecordVersionEncryption",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("models.EncryptionKey"),
		mock.AnythingOfType("[]uint8"),
		mock.AnythingOfType("[]uint8"),
	).Run(func(args mock.Arguments) {
		versionID, ok := args.Get(1).(string)
		assert.True(ok)
		encKey, ok := args.Get(2).(models.EncryptionKey)
		assert.True(ok)
		value, ok := args.Get(3).([]byte)
		assert.True(ok)
		nonce, ok := args.Get(4).([]byte)
		assert.True(ok)

		// Every version lands on the key it was moved to
		assert.Equal(newKey.ID, encKey.ID)
		written[versionID] = encryption.EncryptedData{CipherText: value, Nonce: nonce}
	}).Return(models.RecordVersion{}, nil).Times(len(versions))

	assert.Nil(uut.ReEncryptRecordVersions(utCtx, versions, newKey, mockDatabase))
	assert.Len(written, len(versions))

	for idx, version := range versions {
		reEncrypted, ok := written[version.ID]
		assert.True(ok)

		// A fresh nonce is drawn for every re-encryption
		assert.NotEqual(version.EncNonce, reEncrypted.Nonce)

		// The row as it stands after the move
		reKeyed := version
		reKeyed.EncKeyID = newKey.ID

		_, plainText, err := uut.DecryptData(
			utCtx, newKey.ID, reEncrypted, reKeyed.AssociatedData(), mockDatabase,
		)
		assert.Nil(err)
		assert.Equal(plainTexts[idx], plainText)

		// The associated data of the row it came from no longer authenticates it
		_, _, err = uut.DecryptData(
			utCtx, newKey.ID, reEncrypted, version.AssociatedData(), mockDatabase,
		)
		assert.Error(err)
	}
}

// TestCryptoEngineReEncryptHalts verifies that a version which will not decrypt stops the
// drain where it stands, and that nothing past it is converted.
func TestCryptoEngineReEncryptHalts(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)

	uut := newTestEngine(utCtx, t, "self-signed.crt", "self-signed.key", mockDBClient)

	oldKey := models.EncryptionKey{ID: uuid.NewString(), State: models.EncryptionKeyStateActive}
	mintTestKey(utCtx, t, uut, mockDatabase, &oldKey)

	versions := []models.RecordVersion{}
	for _, plainText := range [][]byte{
		[]byte("intact"), []byte("corrupted"), []byte("never reached"),
	} {
		versions = append(versions, sealTestVersion(utCtx, t, uut, mockDatabase, oldKey, plainText))
	}

	// Something tampered with the second version's cipher text
	versions[1].EncValue[0] ^= 0xff

	newKey := models.EncryptionKey{ID: uuid.NewString(), State: models.EncryptionKeyStateActive}
	mintTestKey(utCtx, t, uut, mockDatabase, &newKey)

	converted := []string{}
	mockDatabase.On(
		"UpdateRecordVersionEncryption",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("models.EncryptionKey"),
		mock.AnythingOfType("[]uint8"),
		mock.AnythingOfType("[]uint8"),
	).Run(func(args mock.Arguments) {
		versionID, ok := args.Get(1).(string)
		assert.True(ok)
		converted = append(converted, versionID)
	}).Return(models.RecordVersion{}, nil).Once()

	err := uut.ReEncryptRecordVersions(utCtx, versions, newKey, mockDatabase)
	assert.Error(err)

	// The failure names the version which blocked the drain
	var blocked encryption.UndecryptableVersion
	assert.True(errors.As(err, &blocked))
	assert.Equal(versions[1].ID, blocked.Version.ID)
	assert.Equal(versions[1].RecordID, blocked.Version.RecordID)
	assert.Equal(oldKey.ID, blocked.Version.EncKeyID)

	// Only the version ahead of it was converted; nothing behind it was touched
	assert.Equal([]string{versions[0].ID}, converted)
}

// TestCryptoEngineFindUndecryptableVersions verifies that the diagnostic reports every
// version which will not decrypt, and converts nothing.
func TestCryptoEngineFindUndecryptableVersions(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)

	uut := newTestEngine(utCtx, t, "self-signed.crt", "self-signed.key", mockDBClient)

	encKey := models.EncryptionKey{ID: uuid.NewString(), State: models.EncryptionKeyStateActive}
	mintTestKey(utCtx, t, uut, mockDatabase, &encKey)

	versions := []models.RecordVersion{}
	for _, plainText := range [][]byte{[]byte("one"), []byte("two"), []byte("three")} {
		versions = append(versions, sealTestVersion(utCtx, t, uut, mockDatabase, encKey, plainText))
	}

	// Nothing is wrong yet
	findings, err := uut.FindUndecryptableVersions(utCtx, versions, mockDatabase)
	assert.Nil(err)
	assert.Empty(findings)

	// Corrupt the middle one, and move a fourth onto a record it does not belong to, which
	// the associated data catches
	versions[1].EncValue[0] ^= 0xff
	versions[2].RecordID = uuid.NewString()

	// The scan does not stop at the first failure, and writes nothing: the mock database
	// carries no expectation for any write
	findings, err = uut.FindUndecryptableVersions(utCtx, versions, mockDatabase)
	assert.Nil(err)
	assert.Len(findings, 2)
	assert.Equal(versions[1].ID, findings[0].Version.ID)
	assert.Equal(versions[2].ID, findings[1].Version.ID)
	assert.Error(findings[0])
}

// TestCryptoEngineLoadKEK verifies that a second primary RSA key pair can be loaded
// without the engine adopting it.
func TestCryptoEngineLoadKEK(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	mockDBClient := mockdb.NewClient(t)

	uut := newTestEngine(utCtx, t, "self-signed.crt", "self-signed.key", mockDBClient)

	// A different key pair has a different ID, and the engine keeps the one it holds
	newKEK, err := uut.LoadKEK(utCtx, encryption.KEKParams{
		CertFile: testCertFixture(t, "user-root.crt"),
		KeyFile:  testCertFixture(t, "user-root.key"),
	})
	assert.Nil(err)
	assert.Len(newKEK.ID(), 64)
	assert.NotEqual(uut.KEKID(), newKEK.ID())

	// Loading the pair the engine already holds yields the ID it reports
	sameKEK, err := uut.LoadKEK(utCtx, encryption.KEKParams{
		CertFile: testCertFixture(t, "self-signed.crt"),
		KeyFile:  testCertFixture(t, "self-signed.key"),
	})
	assert.Nil(err)
	assert.Equal(uut.KEKID(), sameKEK.ID())

	// A key pair is held to the same checks as the engine's own
	for _, entry := range []struct {
		name    string
		params  encryption.KEKParams
		wantErr string
	}{
		{
			name: "file does not exist",
			params: encryption.KEKParams{
				CertFile: testCertFixture(t, "does-not-exist.crt"),
				KeyFile:  testCertFixture(t, "self-signed.key"),
			},
			wantErr: "invalid RSA key pair parameters",
		},
		{
			name: "expired certificate",
			params: encryption.KEKParams{
				CertFile: testCertFixture(t, "user-expired.crt"),
				KeyFile:  testCertFixture(t, "user-expired.key"),
			},
			wantErr: "expired on",
		},
		{
			name: "key does not match certificate",
			params: encryption.KEKParams{
				CertFile: testCertFixture(t, "user-root.crt"),
				KeyFile:  testCertFixture(t, "user-intermediate.key"),
			},
			wantErr: "does not match",
		},
	} {
		_, err := uut.LoadKEK(utCtx, entry.params)
		assert.ErrorContains(err, entry.wantErr, entry.name)
	}
}

// TestCryptoEngineRewrapEncryptionKeys verifies that re-wrapping an encryption key under a
// new primary RSA key pair leaves the symmetric key, and therefore every cipher text
// encrypted with it, untouched.
func TestCryptoEngineRewrapEncryptionKeys(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)

	uut := newTestEngine(utCtx, t, "self-signed.crt", "self-signed.key", mockDBClient)

	encKey := models.EncryptionKey{ID: uuid.NewString(), State: models.EncryptionKeyStateActive}
	mintTestKey(utCtx, t, uut, mockDatabase, &encKey)
	assert.Equal(uut.KEKID(), encKey.KekID)
	originalMaterial := encKey.EncKeyMaterial

	// Data sealed before the rotation, which must survive it
	plainText := []byte("a secret which outlives its wrapping")
	version := sealTestVersion(utCtx, t, uut, mockDatabase, encKey, plainText)

	newKEK, err := uut.LoadKEK(utCtx, encryption.KEKParams{
		CertFile: testCertFixture(t, "user-root.crt"),
		KeyFile:  testCertFixture(t, "user-root.key"),
	})
	assert.Nil(err)

	// The key pair in use is not a rotation target
	sameKEK, err := uut.LoadKEK(utCtx, encryption.KEKParams{
		CertFile: testCertFixture(t, "self-signed.crt"),
		KeyFile:  testCertFixture(t, "self-signed.key"),
	})
	assert.Nil(err)
	assert.Error(uut.RewrapEncryptionKeys(
		utCtx, []models.EncryptionKey{encKey}, sameKEK, mockDatabase,
	))

	// A key wrapped by a key pair which is neither the one in use nor the new one is a hard
	// error rather than an opaque decryption failure
	{
		strayKey := encKey
		strayKey.KekID = "0f9a1c7b3e5d2846a0b1c2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071"
		err := uut.RewrapEncryptionKeys(
			utCtx, []models.EncryptionKey{strayKey}, newKEK, mockDatabase,
		)
		assert.ErrorContains(err, strayKey.KekID)
		assert.ErrorContains(err, uut.KEKID())
		assert.ErrorContains(err, newKEK.ID())
	}

	// A key already carrying the new key pair's ID is skipped: the mock database carries no
	// expectation for a write
	{
		doneKey := encKey
		doneKey.KekID = newKEK.ID()
		assert.Nil(uut.RewrapEncryptionKeys(
			utCtx, []models.EncryptionKey{doneKey}, newKEK, mockDatabase,
		))
	}

	// Re-wrap it
	var rewrapped models.EncryptionKey
	mockDatabase.On(
		"UpdateEncryptionKeyWrapping",
		mock.AnythingOfType("context.backgroundCtx"),
		encKey.ID,
		mock.AnythingOfType("[]uint8"),
		newKEK.ID(),
	).Run(func(args mock.Arguments) {
		material, ok := args.Get(2).([]byte)
		assert.True(ok)
		rewrapped = models.EncryptionKey{
			ID:             encKey.ID,
			EncKeyMaterial: material,
			KekID:          newKEK.ID(),
			State:          models.EncryptionKeyStateActive,
		}
	}).Return(func(
		_ context.Context, _ string, _ []byte, _ string,
	) models.EncryptionKey {
		return rewrapped
	}, nil).Once()

	assert.Nil(uut.RewrapEncryptionKeys(
		utCtx, []models.EncryptionKey{encKey}, newKEK, mockDatabase,
	))
	assert.NotEqual(originalMaterial, rewrapped.EncKeyMaterial)
	assert.Equal(newKEK.ID(), rewrapped.KekID)

	// An engine holding the new key pair unwraps the re-wrapped key, and reads data sealed
	// before the rotation. This is the proof the symmetric key survived.
	{
		mockDatabase2 := mockdb.NewDatabase(t)
		uut2 := newTestEngine(utCtx, t, "user-root.crt", "user-root.key", mockDBClient)
		assert.Equal(newKEK.ID(), uut2.KEKID())

		mockDatabase2.On(
			"GetEncryptionKey",
			mock.AnythingOfType("context.backgroundCtx"),
			encKey.ID,
		).Return(rewrapped, nil).Once()

		_, decrypted, err := uut2.DecryptData(
			utCtx,
			encKey.ID,
			encryption.EncryptedData{CipherText: version.EncValue, Nonce: version.EncNonce},
			version.AssociatedData(),
			mockDatabase2,
		)
		assert.Nil(err)
		assert.Equal(plainText, decrypted)
	}
}

// TestCryptoEngineReEncryptSkipsConvertedVersions verifies that a version already sitting on
// the target key is left where it is.
//
// A drain pages from offset zero, so a rerun of an interrupted rotation hands the engine
// pages holding rows an earlier run already moved. Re-sealing one of those is not corrupting
// — the associated data it would be given is the one it already carries — so nothing
// downstream notices. The skip is the only thing which keeps the rotation from doing the
// whole drain again on every resume.
func TestCryptoEngineReEncryptSkipsConvertedVersions(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtx := context.Background()
	mockDBClient := mockdb.NewClient(t)
	mockDatabase := mockdb.NewDatabase(t)

	uut := newTestEngine(utCtx, t, "self-signed.crt", "self-signed.key", mockDBClient)

	oldKey := models.EncryptionKey{ID: uuid.NewString(), State: models.EncryptionKeyStateActive}
	mintTestKey(utCtx, t, uut, mockDatabase, &oldKey)

	newKey := models.EncryptionKey{ID: uuid.NewString(), State: models.EncryptionKeyStateActive}
	mintTestKey(utCtx, t, uut, mockDatabase, &newKey)

	// A page holding one version still on the old key, and one an earlier run already moved
	pending := sealTestVersion(utCtx, t, uut, mockDatabase, oldKey, []byte("still to move"))
	alreadyMoved := sealTestVersion(utCtx, t, uut, mockDatabase, newKey, []byte("already moved"))

	converted := []string{}
	mockDatabase.On(
		"UpdateRecordVersionEncryption",
		mock.AnythingOfType("context.backgroundCtx"),
		mock.AnythingOfType("string"),
		mock.AnythingOfType("models.EncryptionKey"),
		mock.AnythingOfType("[]uint8"),
		mock.AnythingOfType("[]uint8"),
	).Run(func(args mock.Arguments) {
		versionID, ok := args.Get(1).(string)
		assert.True(ok)
		converted = append(converted, versionID)
	}).Return(models.RecordVersion{}, nil).Once()

	assert.Nil(uut.ReEncryptRecordVersions(
		utCtx, []models.RecordVersion{alreadyMoved, pending}, newKey, mockDatabase,
	))

	// Only the version which had not moved was written
	assert.Equal([]string{pending.ID}, converted)
}

// TestUndecryptableVersionError verifies what a halted rotation reports about the row which
// blocked it.
//
// errors.As matches this type as a target, so finding it in a chain exercises neither
// method. The message is what an operator reads to identify the row, and Unwrap is how the
// authentication failure underneath stays reachable once the maintenance layer has wrapped
// the finding in its own error.
func TestUndecryptableVersionError(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	version := models.RecordVersion{
		ID: db.NewRecordVersionID(), RecordID: uuid.NewString(), EncKeyID: uuid.NewString(),
	}
	cause := models.NewEncryptionError("failed to decrypt cipher text", nil, false)
	finding := encryption.UndecryptableVersion{Version: version, Cause: cause}

	// The message names the row, the record holding it, and the key it would not open with
	assert.Contains(finding.Error(), version.ID)
	assert.Contains(finding.Error(), version.RecordID)
	assert.Contains(finding.Error(), version.EncKeyID)

	assert.Equal(cause, finding.Unwrap())

	// The cause is reachable through the finding rather than buried by it
	var encryptionErr models.EncryptionError
	assert.True(errors.As(error(finding), &encryptionErr))
	assert.Equal(cause, encryptionErr)
}
