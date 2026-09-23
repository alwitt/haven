# `haven` Design

`haven` is an **embeddable** encrypted-at-rest, versioned key-value store. An application
imports it as a Go library, points it at a SQL database and an RSA key pair, and gets a KV
API that transparently encrypts every value it stores and decrypts every value it reads.
The embedding application never touches key material, never chooses a cipher, and never
sees a nonce.

This document is the design reference for the whole system: layering, data model,
cryptography, the system lifecycle, and the maintenance actions that manage cryptographic
material over time. It is written in the present tense and describes the design as
intended; §14 records which parts are built today and which are not.

---

## Contents

- [1. Motivation and scope](#1-motivation-and-scope)
- [2. Architecture](#2-architecture)
- [3. Data model](#3-data-model)
- [4. Cryptography](#4-cryptography)
- [5. System lifecycle](#5-system-lifecycle)
- [6. Encryption key states](#6-encryption-key-states)
- [7. Maintenance actions](#7-maintenance-actions)
- [8. Guard rails](#8-guard-rails)
- [9. KV store semantics](#9-kv-store-semantics)
- [10. Audit log](#10-audit-log)
- [11. Error taxonomy](#11-error-taxonomy)
- [12. Persistence and deployment](#12-persistence-and-deployment)
- [13. Testing strategy](#13-testing-strategy)
- [14. Implementation status](#14-implementation-status)
- [15. Non-goals and deferred](#15-non-goals-and-deferred)

---

## 1. Motivation and scope

`haven` exists for applications that must persist secrets — credentials, tokens,
configuration containing either — and want them encrypted at rest without taking on a key
management service as a dependency. The embedding application supplies one RSA key pair;
`haven` does everything else.

**`haven` is a library, not a service.** This single fact drives most of what follows. A
service can serialize its own operations: it owns its process, it can refuse requests
during a migration, it can hold a lock. A library has none of that. Its code runs inside
someone else's process, and that process may be horizontally scaled, so N copies of
`haven` may be operating on the same database with no channel between them. Every design
decision about key rotation in §5-§8 is a consequence of not being able to coordinate
those copies at runtime.

### 1.1 What it guarantees

- **Values are encrypted at rest.** Plain text is never written to the database. The
  encryption key material itself is stored only in wrapped form (§4).
- **Values are versioned.** Recording a key does not overwrite its previous value; it
  appends a new version. History is retained until the record is deleted.
- **Values are bound to their row.** A cipher text cannot be moved to a different record,
  a different version, or re-associated with a different key without failing
  authentication (§4.2).
- **Lifecycle events are audited.** Key creation, key retirement, key deletion, record
  creation, record deletion, and rotation boundaries are recorded in an append-only table.

### 1.2 What it is not

- **Not a service.** There is no network API, no daemon, no RPC.
- **Not an access control system.** Anyone who can call the API can read every value. If
  the embedding application needs authorization, it implements it.
- **Not multi-tenant.** One database is one store. Two `haven` instances on the same
  database are copies of each other, not isolated tenants.
- **Not a KMS.** The RSA key pair is supplied as PEM files by the embedding application.
  `haven` does not generate it, store it, or protect it beyond holding the parsed private
  key in process memory.

---

## 2. Architecture

```
  haven                       entry point
    │                         NewProtectedKVStore, NewMaintenanceRunner
    ├─────────────┐
    ▼             ▼
  store      maintenance      application facing
    │             │           ProtectedKVStore / Runner
    └──────┬──────┘
           ▼
      encryption               all cryptography; owns the key tables
           │                   CryptographyEngine
           ▼
          db                   persistence; GORM and transactions
           │                   Client / Database
           ▼
        models                 entities, ENUMs, validation, error types
```

`store` and `maintenance` are siblings. `store` is the steady-state data path; `maintenance`
is the lifecycle path. They are never active at the same time (§7.4).

### 2.1 The cryptography engine owns key material

`CryptographyEngine` is the only component that holds the KEK, the only one that wraps or
unwraps symmetric key material, and the only one that maintains the decrypted key cache.
The steady-state data path reaches `encryption_keys` only through it: a caller that
bypassed it would see cipher text where it expected a key, or would silently desynchronize
the cache.

**`maintenance` is the exception.** A key's *state* and a key's *existence* are not
cryptographic operations, so maintenance drives them through `db.Database` directly —
`MarkEncryptionKeyRetired` and `DeleteEncryptionKey` live there, not on the engine (§6.2).
Maintenance still goes through the engine for everything cryptographic: minting a key,
unwrapping one, re-wrapping one under a new KEK, and re-encrypting record values. The
engine converts what it is handed — a page of versions, a page of keys — and the caller
owns the paging, the transaction boundaries and the state transitions around them (§2.2).

The cost of this split is cache coherence: a key retired through `db` stays `ACTIVE` in an
engine's cache until that entry's TTL lapses (§4.3). It is harmless, because both states
decrypt and because no KV store runs during a maintenance action (§7.4).

### 2.2 Transactions compose through `activeDBClient`

Every public method on `store` and `encryption` takes a trailing `activeDBClient
db.Database` argument. Passing `nil` means "open your own transaction"; passing a live
`Database` means "join the one I already have". This is what allows a maintenance action to
perform a multi-step operation atomically while reusing the same per-entity methods the
steady-state path uses.

**`maintenance` is the exception, and takes no `activeDBClient` anywhere.** Its transaction
*structure* is the design, not an implementation detail: §7.2 (a) has to commit on its own,
before any work starts, or the write barrier §8.1 depends on is invisible to other
connections. An action running inside a caller's transaction would publish nothing until the
end and leave nothing committed for an interrupted action to resume from — which is to say
it would not be the operation §7 describes. The read-only calls follow the same rule rather
than splitting the package's convention in two.

[`db.ActiveSessionWrapper`](db/client.go) is the single place that makes the decision:

```go
if activeDBClient == nil {
    return persistence.UseDatabaseInTransaction(ctx, coreLogic)
}
return coreLogic(ctx, activeDBClient)
```

Two consequences worth knowing:

- `UseDatabaseInTransaction` returns the callback's error **unwrapped**. Error type
  matching with `errors.As` therefore works across the transaction boundary (§11).
- A method called with a non-nil `activeDBClient` does **not** open a transaction, so it
  cannot commit. Whoever opened the transaction owns the commit.

### 2.3 `models` is dependency-free

`models` holds the entities, the string ENUM types with their `Values()` and
`ValidateNextState` methods, the validator macros, and the two `haven`-specific error
types. It imports `goutils` and the validator, nothing from `haven`. Every other package
depends on it; it depends on none of them.

---

## 3. Data model

Five tables. [`db/tables.go`](db/tables.go) maps them to GORM; the generated Atlas
migrations under [`migrations/`](migrations/) are the authority on the SQL shape.

### 3.1 `system_params`

A **singleton**. Exactly one row, with the primary key fixed to the literal
`system-parameters` (`db.GlobalSystemParamEntryID`, enforced by
`validate:"required,oneof=system-parameters"`). It is created on first read if absent.

| Column | Notes |
|---|---|
| `id` | always `system-parameters` |
| `state` | the system lifecycle state (§5) |
| `created_at`, `updated_at` | |

This row is the system's lifecycle register. Because it is a single row read by primary
key, checking it is cheap enough to do on the write path (§8).

### 3.2 `encryption_keys`

One row per Data Encryption Key (DEK).

| Column | Notes |
|---|---|
| `id` | UUID |
| `enc_key_material` | the DEK, **wrapped** by the KEK (§4). Never plain text. |
| `kek_id` | identifies the KEK that wrapped `enc_key_material` (§4.5) |
| `state` | `ACTIVE` or `RETIRED` (§6) |
| `created_at`, `updated_at` | |

### 3.3 `records`

One row per key in the KV store.

| Column | Notes |
|---|---|
| `id` | UUID |
| `name` | the KV key. **Unique** — one record per name. |
| `created_at`, `updated_at` | |

### 3.4 `record_versions`

One row per value ever recorded against a record.

| Column | Notes |
|---|---|
| `id` | **ULID**, not UUID — see below |
| `record_id` | FK → `records(id)`, `ON DELETE CASCADE` |
| `enc_key_id` | FK → `encryption_keys(id)`, `ON DELETE RESTRICT` |
| `enc_value` | the AEAD cipher text (plain text + 16-byte tag) |
| `enc_nonce` | the 24-byte XChaCha20 nonce, unique per version |
| `created_at`, `updated_at` | caller-supplied timestamp |

Version IDs are ULIDs ([`db.NewRecordVersionID`](db/record.go)) so they sort
lexicographically by creation time. This gives ordered version history without depending on
`created_at`, which is caller-supplied and therefore not monotonic.

The two foreign keys differ deliberately:

- `record_id` **cascades**. Deleting a record is meant to delete its history.
- `enc_key_id` **restricts**. Deleting an encryption key must never delete data. Under
  `CASCADE`, removing a key silently destroys every version encrypted with it. Under
  `RESTRICT` the delete fails instead, and §7.2 turns that failure into a completion check.

`RESTRICT` requires that no row *references* the key being deleted. It does not require
that those rows be deleted: DEK rotation satisfies it by **updating** every version to
reference the new key (§7.2), which preserves the full version history. Deleting versions
to satisfy the constraint would defeat the purpose of the store.

### 3.5 `system_audit_events`

Append-only lifecycle history. See §10.

| Column | Notes |
|---|---|
| `id` | ULID, so events sort by occurrence |
| `type` | event type ENUM |
| `metadata` | JSON, shape determined by `type` |
| `created_at`, `updated_at` | |

---

## 4. Cryptography

`haven` uses **envelope encryption**. There are two layers of key:

- The **KEK** (Key Encryption Key) is the RSA key pair supplied by the embedding
  application as PEM files. It never encrypts record data. Its only job is to wrap and
  unwrap DEKs.
- A **DEK** (Data Encryption Key) is a 32-byte symmetric key that encrypts record values.
  It is generated by `haven`, stored wrapped in `encryption_keys.enc_key_material`, and
  exists in plain form only inside libsodium secure memory.

All primitives come from [`cgoutils/crypto`](https://github.com/alwitt/cgoutils), which
wraps libsodium.

| Role | Algorithm | Parameters |
|---|---|---|
| KEK wrap/unwrap | RSA-OAEP, SHA-512 MGF1, no label | key size set by the supplied certificate |
| Record value encryption | XChaCha20-Poly1305 (IETF) | 32-byte key, 24-byte nonce, 16-byte tag |
| Randomness | libsodium CSPRNG | |

The separation buys the property that makes rotation tractable: **rotating the KEK does not
touch record data.** Only the ~one row per DEK in `encryption_keys` is re-wrapped (§7.3).

### 4.1 KEK loading and certificate validation

The KEK is supplied as a certificate PEM plus a private key PEM, optionally with a CA
bundle PEM. [`loadRSAKeyPair`](encryption/setup.go) reads all three with `os.ReadFile`,
parses them, and then applies four checks in order:

1. **Validity window.** `NotBefore <= now <= NotAfter`, with `now` taken as
   `time.Now().UTC()`. Local time is never used.
2. **Chain**, only if a CA bundle is supplied. The bundle is split by walking its PEM
   blocks: a certificate that verifies its own signature (`CheckSignatureFrom(self)`) is a
   trust anchor and goes into the root pool; everything else is an intermediate. A bundle
   with no certificates, or with no self-signed root, is rejected outright rather than
   silently trusting nothing. The chain is then built with `x509.Verify`, with
   `KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}` — an empty `KeyUsages` defaults to
   server auth, which a key-encryption certificate has no reason to carry.
3. **Key matches certificate.** The parsed private key's public half must equal the public
   key in the certificate. Without this a mismatched pair fails much later, as an opaque
   OAEP error at first use.
4. **Revocation is never checked.** No CRL, no OCSP. This is a deliberate limitation, not
   an omission: a library with no network dependency cannot fetch revocation data. It is
   documented on `CryptographyEngineParams.PrimaryRSACACertFile` so the embedder knows.

Supplying the CA bundle is optional. Without it, only the validity window and the key match
are checked.

### 4.2 Associated data binds a cipher text to its row

Every record value is sealed with AEAD associated data (AAD) built from the row's identity:

```
record_id | version_id | enc_key_id
```

produced by [`models.RecordVersion.AssociatedData()`](models/record.go). The AAD is
authenticated but not stored — it is recomputed from the row at decryption time.

The effect is that `(enc_value, enc_nonce, enc_key_id)` cannot be copied from one version
or record to another: the AAD no longer matches and authentication fails. Without it, an
attacker with write access to the database could swap one secret's cipher text for
another's undetectably.

Two consequences follow, and both matter:

- **This is part of the on-disk format.** Changing how the AAD is composed makes every
  existing version undecryptable. It cannot be changed without a data migration that
  re-encrypts everything.
- **DEK rotation must recompute it.** Re-encrypting a version under a new key changes
  `enc_key_id`, therefore changes the AAD. The rotation decrypts with the old AAD and
  re-seals with the new one (§7.2). The version ID and record ID are unchanged, so the row
  keeps its identity.

An empty AAD slice and a `nil` AAD are treated as the same thing (`normalizeAdditional`),
because the AEAD dereferences the first byte of any non-`nil` slice.

### 4.3 The DEK cache

Unwrapping a DEK is an RSA private key operation — expensive enough that doing it per
record operation is not viable. `CryptographyEngine` therefore caches decrypted DEKs
in-process:

- The decrypted key material is held in **libsodium secure memory**
  (`cgoCrypto.SecureCSlice`), not on the Go heap, so it is not swapped to disk and is
  zeroed on free.
- Each entry carries an `expiresAt`. Within the TTL the entry is used as is. After it
  lapses, the key row is re-read from the database and the entry refreshed.
- If the re-read shows unchanged `enc_key_material`, the already-decrypted key is reused
  and only the metadata and TTL are refreshed — the RSA unwrap is skipped.
- A key which can still decrypt is cached, which is both states in §6. Retired keys are
  cached deliberately: the §7.2 (c) drain decrypts under the retired key for every version
  it moves, so evicting it would cost an RSA unwrap per row.
- A KEK rotation is the one thing which changes `enc_key_material` for a key already
  cached. §7.3 (b) writes the new row and the existing decrypted key straight into the
  cache, because the "material unchanged" path above would miss and the engine would try to
  unwrap the *new* material with the *old* private key.

`KeyCacheTTL` is therefore a **staleness bound on cross-instance visibility**: a key state
change made by another process becomes visible to this one only after the TTL lapses.
Changes made through this instance take effect in its cache immediately. `KeyCacheTTL: 0`
re-validates on every use.

Eviction does not zero the secure buffer. An in-flight AEAD operation may still hold a
reference to it; libsodium zeroes and frees it once the last reference is gone.

### 4.4 Input guards

The cgoutils AEAD indexes `&buf[0]` on its inputs, so a zero-length buffer is a panic, not
an error. Two guards prevent a caller — or a corrupted row — from reaching it:

- **`EncryptData` refuses empty plain text**, before any key lookup. `store` refuses an
  empty value even earlier, before opening a transaction, so a bad call costs no database
  round trip.
- **`DecryptData` refuses cipher text at or below the tag size.** The check is
  `aead.ExpectedPlainTextLen(len(cipherText)) <= 0` rather than a literal `len < 16`, which
  keeps the tag size owned by cgoutils. It is `<= 0` and not `< 0` because a cipher text of
  exactly 16 bytes yields a zero-length plain text, which `Unseal` also cannot handle.

A short nonce is caught separately by the copy-length check in `setupAEAD`.

### 4.5 `kek_id`

Each DEK row records which KEK wrapped it. The value is the hex-encoded SHA-256 of the
wrapping public key's SPKI DER (`x509.MarshalPKIXPublicKey`).

SPKI is the right input because it is a property of the **key**, not the certificate. A
certificate renewal that keeps the same key pair produces the same `kek_id`, so renewal
requires nothing from `haven` — which is the common case and should be free. Only a genuine
key change, which is the rare case, changes it.

`kek_id` does two jobs:

1. It makes a KEK mismatch legible. An instance configured with the wrong KEK fails with
   "DEK wrapped by KEK `abc…`, loaded KEK is `def…`" instead of an opaque OAEP decryption
   failure.
2. It is the **resume cursor** for KEK rotation (§7.3). This is the more important of the
   two: without it, a rotation interrupted halfway cannot tell which rows it already did.

---

## 5. System lifecycle

The store's cryptographic material has a lifecycle, and `system_params.state` is where it
lives. Four states:

```
                    ┌──────────────────────────┐
                    │    PRE_INITIALIZATION    │
                    └─────────────┬────────────┘
                                  │ Initialize
                                  ▼
   ┌────────────────────────┐   ┌───────────┐   ┌─────────────────────────┐
   │ DEK_ROTATION_IN_       │◀──┤           ├──▶│ KEK_ROTATION_IN_        │
   │ PROGRESS               ├──▶│   READY   │◀──┤ PROGRESS                │
   └────────────────────────┘   └───────────┘   └─────────────────────────┘
```

| State | Meaning | KV stores |
|---|---|---|
| `PRE_INITIALIZATION` | No DEK exists. The store has never been initialized. | refused |
| `READY` | Exactly one `ACTIVE` DEK. Normal operation. | permitted |
| `DEK_ROTATION_IN_PROGRESS` | A DEK rotation is underway or was interrupted. | refused |
| `KEK_ROTATION_IN_PROGRESS` | A KEK rotation is underway or was interrupted. | refused |

Only `READY` permits the steady-state data path. Every other state means a maintenance
action owns the system.

### 5.1 Transitions are compare-and-swap

A transition is three steps, not two:

1. Read the current state `S`.
2. `ValidateNextState(S → new)` rejects illegal edges from the transition map in
   [`models/system.go`](models/system.go).
3. `UPDATE system_params SET state = <new> WHERE id = 'system-parameters' AND state = S`.

If step 3 affects zero rows, something changed the state between the read and the write,
and the action aborts rather than overwriting. This is what makes two operators running
the same maintenance action concurrently safe without a lock: one wins, the other gets a
clear error.

The transition map stays as the single declaration of the state graph; the CAS is what
enforces it under concurrency.

### 5.2 The `READY` invariant

> `state = READY` ⟺ exactly one `ACTIVE` key **and** zero `RETIRED` keys.

This is checkable at any time and is the basis of every resume rule in §7. A `RETIRED` key
existing at all means a DEK rotation is incomplete.

### 5.3 Why there is no `INITIALIZING` state

An earlier version of the schema had `PRE_INITIALIZATION → INITIALIZING → RUNNING`. Both
`INITIALIZING` and `RUNNING` are gone: `RUNNING` is renamed `READY`, and `INITIALIZING` is
deleted outright.

`INITIALIZING` would only earn its place if initialization needed to be resumable. It does
not: minting a single DEK is one RSA operation and one insert, so the whole of
`Initialize` fits in one transaction (§7.1). A crash rolls back to a clean
`PRE_INITIALIZATION`, and the retry starts from scratch. There is no partial state to name.

The rotations are different — they take time proportional to the data, so they cannot be
one transaction, so they do need states. That asymmetry is the whole reason two of the four
states exist and a third does not.

---

## 6. Encryption key states

Two states, both reachable only through maintenance actions.

| State | `EncryptData` | `DecryptData` | Cached |
|---|---|---|---|
| `ACTIVE` | yes | yes | yes |
| `RETIRED` | **no** | yes | yes |

`RETIRED` means **decrypt-only**. It is the state a DEK occupies between being superseded
and having the last version re-encrypted away from it. DEK rotation depends on it: the
rotation must decrypt data under the old key while writing new data under the new one, so
"old key" cannot mean "unusable key".

### 6.1 Why `INACTIVE` is gone

The previous schema had `ACTIVE` / `INACTIVE`, where `INACTIVE` refused decryption. That
was part of an earlier, incomplete attempt at lifecycle management, and it is a data-loss
trap: marking a key inactive makes every version encrypted with it unreadable while leaving
the rows in place, looking intact. It offers no security benefit, because the wrapped key
and the cipher text are both still in the database.

`RETIRED` replaces it and covers the only legitimate need.

### 6.2 Key state is not part of the data path

`CryptographyEngine` exposes no way to change a key's state or to delete one.
`MarkEncryptionKeyActive`, `MarkEncryptionKeyInactive` and `DeleteEncryptionKey` are not on
it.

The line is not "reads versus writes" — the engine writes key rows, through
`NewEncryptionKey` and `RewrapEncryptionKeys`. It is **cryptographic versus
administrative**. Minting a key, unwrapping one and re-wrapping one under a different KEK
all require the KEK, so they are the engine's. A key's *state* and a key's *existence*
require nothing cryptographic at all, so they stay on `db` for `maintenance` (§2.1).

`db.Database` keeps `MarkEncryptionKeyRetired` and `DeleteEncryptionKey`, which only
`maintenance` calls (§2.1). A key's state and a key's existence are consequences of
maintenance actions and nothing else: §7.1 and §7.2 (b) are the only things that create
keys, §7.2 (b) the only thing that retires one, §7.2 (d) the only thing that deletes one.

There is no equivalent of `MarkEncryptionKeyActive` at any layer. It was the one path that
could produce a second `ACTIVE` key outside a rotation transaction, which would make "the
working key" an actual choice rather than a lookup — and with `RETIRED → ACTIVE` off the
state graph, reactivation has no meaning left.

---

## 7. Maintenance actions

The `maintenance` package owns every operation that changes cryptographic material. It is
constructed with the **current** KEK — the same certificate, key and optional CA bundle the
cryptography engine takes — and exposes four operations:

| Operation | From → to | Purpose |
|---|---|---|
| `Status(ctx)` | — | report system state, key inventory, and outstanding work |
| `Initialize(ctx)` | `PRE_INITIALIZATION` → `READY` | mint the first DEK |
| `RotateEncryptionKey(ctx)` | `READY` → `READY` | replace the DEK, re-encrypt all data |
| `RotateKEK(ctx, newCert, newKey, newCA)` | `READY` → `READY` | re-wrap all DEKs under a new KEK |
| `ListUndecryptableVersions(ctx)` | `DEK_ROTATION_IN_PROGRESS`, unchanged | report versions a rotation cannot decrypt (§7.2.1) |
| `PurgeUndecryptableVersions(ctx)` | `DEK_ROTATION_IN_PROGRESS`, unchanged | destroy those versions (§7.2.1) |

The embedding application is expected to expose these as an administrative command it runs
with itself stopped (§7.4).

`RotateKEK` takes the **new** KEK as arguments because the runner already holds the old
one: the old KEK is the one the running system is configured with, and it is needed
throughout the rotation to unwrap rows not yet converted.

### 7.1 `Initialize`

A single transaction:

| Step | Action |
|---|---|
| 1 | Generate a 32-byte DEK in secure memory, wrap it under the KEK, insert it `ACTIVE` with `kek_id` |
| 2 | CAS `PRE_INITIALIZATION → READY` |
| 3 | Audit `SYSTEM_INITIALIZED` |

**Resume rule:** none needed. A crash rolls the whole thing back, leaving
`PRE_INITIALIZATION` and no keys. Rerun.

Initialization is deliberately *not* done lazily on first use. Doing it in the KV store
constructor — which is where it used to live — means two application instances starting
against an empty database race, and both mint a key. Making it an explicit operator action
removes the race by removing the concurrency.

### 7.2 `RotateEncryptionKey`

Four steps, with three separate transaction boundaries. The boundaries are the design; the
work between them is mechanical.

| Step | Transaction | Action |
|---|---|---|
| a | own | CAS `READY → DEK_ROTATION_IN_PROGRESS`; audit rotation start |
| b | own | Mark the `ACTIVE` key `RETIRED`; mint a new `ACTIVE` key under the current KEK; audit both |
| c | one per page | Drain versions under `RETIRED` keys: decrypt under the retired key with the old AAD, re-seal under the `ACTIVE` key with a **fresh nonce** and the recomputed AAD, update `enc_value`, `enc_nonce`, `enc_key_id` |
| d | own | Delete the `RETIRED` keys **and** CAS to `READY`; audit deletion and rotation completion |

**Why (a) is its own transaction.** It is the write barrier. Committing it separately, and
before any work starts, is what lets the persistence layer refuse new record writes for the
whole duration (§8). If it were part of a larger transaction, other connections would not
see it.

**Why (b) is atomic.** Retiring the old key and minting the new one together keeps the
§5.2 invariant intact at every commit boundary: there is never a moment, visible to another
connection, with two `ACTIVE` keys or none.

**Why (d) is atomic.** This is the subtle one. Under `DEK_ROTATION_IN_PROGRESS`, the
resuming action must distinguish "never started" from "finished everything but crashed
before the flip". If the delete and the flip were separate, both cases would present as
*no `RETIRED` keys, state still in progress*, and a resume would pointlessly mint a third
key and re-encrypt the entire database. With (d) atomic, the two cases are distinguishable:

**Resume rule:** on entry with state `DEK_ROTATION_IN_PROGRESS`,

- no `RETIRED` key exists ⇒ step (b) never committed ⇒ start at (b);
- a `RETIRED` key exists ⇒ resume the drain at (c).

Step (c) is idempotent at row granularity because `record_versions.enc_key_id` *is* the
progress marker — a row already converted no longer matches the drain query.

**The drain updates rows; it never deletes them.** Each version keeps its ID, its
`record_id` and its position in the record's history. Only the three encryption columns
change. A DEK rotation is invisible in the version history the embedding application sees,
which is the point: rotating a key is a cryptographic operation, not a data operation.

**`RESTRICT` makes (d) a completion proof.** If any version still references a retired key,
the delete violates the foreign key, the transaction aborts, and the state stays
`DEK_ROTATION_IN_PROGRESS`. The rotation cannot report success over incomplete work. Under
`CASCADE` the same situation silently deletes the stragglers — which is to say, silently
destroys data. This is why §3.4 specifies `RESTRICT`.

#### 7.2.1 Versions that cannot be re-encrypted

Step (c) assumes every version under the retired key decrypts. One thing breaks that
assumption: a row whose `enc_value`, `enc_nonce` or identity columns have been corrupted or
tampered with. The AEAD refuses to unseal it, so there is nothing to re-encrypt, and the
row's reference to the retired key cannot be cleared.

The consequence is severe and must be stated plainly: **one such row blocks the rotation
permanently.** Step (d) cannot delete the retired key, the state stays
`DEK_ROTATION_IN_PROGRESS`, and §8.3 means no KV store can be constructed until it is
resolved. The store is unusable until an operator intervenes.

That is the correct default. A decryption failure under the right key is evidence of
corruption or tampering — the AAD (§4.2) exists specifically to detect the latter — and
silently discarding the row would destroy both the data and the evidence. So step (c)
**halts** on the first such version, naming the version ID, its record, and the retired key,
and commits nothing further.

Recovering requires a deliberate act by the operator, of which there are two:

1. **Restore the rows** from a backup and rerun the rotation. Preferred whenever a backup
   exists, since it is the only option that recovers the data.
2. **Purge them** with `PurgeUndecryptableVersions`, then rerun the rotation, which resumes
   at step (c) and now finds nothing it cannot convert.

Both need the operator to know the full extent of the damage first, which is why the
diagnostic is a separate call from the destructive one:

| Operation | Effect |
|---|---|
| `ListUndecryptableVersions(ctx)` | Read-only. Attempts to decrypt every version under a retired key; returns a summary — version ID, record ID, record name, `created_at` — of each that fails. |
| `PurgeUndecryptableVersions(ctx)` | Deletes exactly those versions through the persistence layer's `PurgeRecordVersion`, audits each one individually (§10), and returns the same summary describing what it destroyed. |

Both stand on the engine's `FindUndecryptableVersions`, which attempts the decryption and
returns one `UndecryptableVersion` per failure without converting anything. The record
*name* in the summary is not part of that finding — the engine has no business reading the
records table — so `maintenance` joins it on.

Two operations rather than one with a `dryRun` flag, for the same reason purging is not a
flag on `RotateEncryptionKey`: reading and destroying should not be one command away from
each other. Listing first is also the only way to size the problem — step (c) halts on the
*first* failure, so discovering fifty bad rows by rerunning the rotation would take fifty
runs.

Both are callable only under `DEK_ROTATION_IN_PROGRESS`. Outside a rotation there are no
retired keys (§5.2), so the scan has no scope; and an undecryptable version under the
`ACTIVE` key blocks nothing, so destroying it has no forcing function and is not this API's
business. Both are O(versions under retired keys) in AEAD operations — this is a
maintenance-window diagnostic, not a health check.

`PurgeUndecryptableVersions`, and the `db.Database.PurgeRecordVersion` beneath it, are the
**only** path in `haven` that deletes a record version without deleting its record. Everything else that removes versions does so by cascade from
`DeleteRecord`.

### 7.3 `RotateKEK`

| Step | Transaction | Action |
|---|---|---|
| a | own | CAS `READY → KEK_ROTATION_IN_PROGRESS`; audit rotation start |
| b | own | For each DEK whose `kek_id` ≠ the new KEK's: unwrap with the old KEK, wrap with the new, set `kek_id` |
| c | own | Assert no DEK remains under the old `kek_id`; CAS to `READY`; audit completion |

**Step (b) does not page.** A KEK rotation opens from `READY`, and §5.2 bounds `READY` to
exactly one DEK, so there is nothing to page over. The engine converts whatever list it is
handed, so this is a property of the caller, not a limitation.

**Record versions are never touched.** The AAD binds the DEK's *ID*, not its wrapping, so
re-wrapping a DEK leaves every cipher text valid. This is the payoff of envelope
encryption: KEK rotation is O(number of keys), not O(number of versions).

**Resume rule:** `kek_id` is the cursor. A row already carrying the new `kek_id` is done; a
row carrying the old one is not. Rerunning with the same pair picks up exactly where it
stopped. The skip is checked *before* anything reads the key material, because unwrapping
an already-converted row with the old KEK fails with an opaque OAEP error rather than a
legible one.

**The engine does not adopt the new KEK.** It keeps the pair it was constructed with for
the whole rotation, because that is the only thing which can unwrap the rows not yet
converted, and a resumed rotation depends on it. Once the rotation completes the process
must be restarted with the new KEK configured — which §7.4 already requires, since no
instance runs during a maintenance action anyway.

**Unknown `kek_id`.** A DEK whose `kek_id` matches neither the old nor the new KEK is a
hard error naming all three values. That is the "operator supplied the wrong pair" case,
and it must fail loudly before any row is touched rather than producing unwrappable rows.

### 7.4 Operating constraints

These are requirements on the operator, not properties `haven` can enforce. They are stated
here because the design depends on them.

- **No embedding application instance may be running during a maintenance action.** `haven`
  cannot coordinate across processes, so this is the constraint that replaces the
  coordination it cannot do. §8 provides guard rails that bound the damage when the rule is
  broken; they do not make breaking it safe.
- **Rotations roll forward only.** Once the drain — §7.2 (c) or §7.3 (b) — has converted
  its first row, there is no going back: the old cipher text or the old wrapping is gone
  for that row. An interrupted rotation must be rerun to completion, not abandoned.
- **An interrupted action leaves the system blocked.** State stays at
  `…_IN_PROGRESS`, so KV stores refuse to start. This is deliberate fail-closed behaviour.
  The error surfaced to the embedding application must say which state the system is in and
  that a maintenance action must be completed, or the operator will read it as corruption.
  §7.2.1 is the worst case: a rotation that cannot complete without an operator destroying
  data or restoring it from backup.
- **Run one action at a time.** Concurrent runs are made safe by the CAS in §5.1, but there
  is no reason to attempt them.

### 7.5 Paging over a changing result set

Both drains — §7.2 (c) and §7.3 (b) — select rows by the very column they then modify. This
makes offset-based paging **wrong**: as rows leave the result set, the offset skips rows
that shifted into positions already passed.

The correct pattern is to always request the *first* page and loop until it comes back
empty:

```go
for {
    batch, err := listRemaining(ctx, pageSize)   // limit=pageSize, no offset
    if err != nil || len(batch) == 0 {
        return err
    }
    // convert batch, committing as we go
}
```

This is a usage rule for the existing
[`ListVersionsEncryptedByKey`](db/database.go), which already accepts
`RecordVersionQueryFilter` with `Limit`/`Offset`. No signature change is needed — only the
discipline to never set `Offset` on these queries.

**`PurgeUndecryptableVersions` (§7.2.1) needs the opposite rule**, and getting the two
confused is a silent data-skipping bug. It does not modify the predicate — it deletes some
rows and *keeps* the rest, so the result set never empties and the loop above would spin
forever on the rows it keeps. It must therefore page by offset, advancing the offset by the
number of rows it **kept**, not by the page size:

```go
offset := 0
for {
    batch, err := listUnderRetiredKeys(ctx, pageSize, offset)
    if err != nil || len(batch) == 0 {
        return err
    }
    kept := purgeFailures(ctx, batch)   // deletes the undecryptable ones
    offset += kept
}
```

`ListUndecryptableVersions` deletes nothing, so plain offset paging is correct for it.

The distinction is general: **a drain that empties its own result set pages from zero; a
filter that removes only some rows advances past the ones it leaves behind.**

---

## 8. Guard rails

`haven` cannot stop an embedding application from running during a maintenance action. It
can make the attempt fail loudly and early, and that is worth doing: the failure mode it
prevents is a record write landing under a key that the rotation has already finished
migrating, which would leave a version nothing will ever re-encrypt.

### 8.1 The persistence layer refuses record writes outside `READY`

[`DefineNewRecord`](db/record.go), [`DefineNewVersionForRecord`](db/record.go) and
[`DeleteRecord`](db/record.go) read `system_params` at the top of their own transaction and
fail with a `goutils.RuntimeError` unless the state is `READY`.

The check lives in the persistence layer rather than in `store` because it is the last
point before the data, so it catches every caller including ones that bypass `store`. Its
cost is a primary-key read of a single-row table inside a transaction that is already doing
inserts and, in the version case, an AEAD operation — negligible by comparison.

Reads are **not** guarded. During a DEK rotation every version is decryptable either under
a `RETIRED` key or under the new `ACTIVE` one, and during a KEK rotation the DEK material
is unchanged. Reads stay correct throughout, so there is no reason to block them.

### 8.2 Maintenance must not trip its own guard

The drain in §7.2 (c) writes `record_versions`, which is exactly what §8.1 forbids outside
`READY`. The resolution is a separate, **unguarded** persistence method used only by
`maintenance` — `UpdateRecordVersionEncryption(ctx, versionID, encKey, value, nonce)` or
similar — that updates the encryption columns of an existing version.

This is a real benefit of putting the guard on specific methods rather than on a connection
or a transaction: the guarded set is exactly the three methods `store` uses to mutate record
data. `RecordEncryptionKey` is likewise unguarded, since only maintenance creates keys.

### 8.3 The KV store constructor checks state and stops minting keys

`store.NewProtectedKVStore` does not create encryption keys. Minting is a maintenance
action (§7.1) and nothing else. The constructor:

1. refuses to construct unless the state is `READY`, naming the state it found;
2. reads the first `ACTIVE` key into `workingKey`, and refuses if there are none.

Both reads share one transaction, so the key is the one that state refers to.

Failing at construction is much better than failing at first write: the embedding
application discovers the problem at startup, where it has somewhere sensible to report it.

**Why "the first" rather than "the single one".** §5.2 makes them the same key on any
healthy system, so the distinction only arises where the invariant is already broken. Taking
the first keeps the constructor reporting the problem it actually has — no key it can
encrypt under — rather than adjudicating an invariant it did not create and cannot repair.
`Status` (§7) is where an operator checks the invariant, and it reports it directly.

### 8.4 What the guard rails do not do

**Snapshot isolation.** A transaction that began before the §7.2 (a) barrier committed can
still observe `READY` and proceed. The barrier bounds the window; it does not eliminate it.
This is precisely why §7.4 is an operator requirement and not merely an implementation
detail.

**Stale instances.** An application instance that survives a rotation window holds a
`workingKey` referring to a key that no longer exists. Once the state returns to `READY`
its next write passes the guard and then violates the `enc_key_id` foreign key. It fails
loudly and writes nothing — which is the desired outcome, and another reason the `RESTRICT`
change in §3.4 matters.

---

## 9. KV store semantics

`store.ProtectedKVStore` is the steady-state API. Every method takes an optional
`activeDBClient` (§2.2).

| Method | Behaviour |
|---|---|
| `RecordKeyValue(ctx, key, value, timestamp, …)` | Append a new version for `key`, creating the record if absent. Returns the record and the new version. |
| `ListKeyVersions(ctx, key, …)` | The record and all its versions, newest first. |
| `GetValueOfKeyAtVersionID(ctx, versionID, …)` | Fetch a version by ID and decrypt it. |
| `GetValueOfKeyAtVersion(ctx, versionEntry, …)` | Decrypt an already-fetched version. No database access. |
| `DeleteKey(ctx, key, …)` | Delete the record and, by cascade, every version of it. |

### 9.1 The write path

`RecordKeyValue` runs in one transaction:

1. **Reject an empty value** before the transaction opens — the AEAD cannot seal one
   (§4.4), and failing early costs no round trip.
2. Look up the record by name. A `goutils.NotFoundError` — and *only* that — means the
   record does not exist yet and must be created. Any other error is a genuine failure and
   aborts the write. (Treating every lookup error as not-found turns a transient SQL
   failure into a duplicate-name insert attempt.)
3. Generate the version ID **before** encrypting. The ID is part of the AAD (§4.2), so it
   must be fixed first. This is why `DefineNewVersionForRecord` takes a caller-supplied
   version ID rather than generating its own.
4. Encrypt the value under `workingKey` with the AAD for the row being created.
5. Insert the version.

### 9.2 `workingKey` is resolved once

The working key is read at construction and never refreshed. In the general case that would
be a bug — another instance could retire the key underneath, and this instance's writes
would fail permanently.

Under §7.4 it is correct: the only thing that can change the active key is a maintenance
action, and no application instance runs during one. Every instance that starts after the
action reads the new key at construction. Instances that should not have been running fail
loudly (§8.4) rather than writing data the rotation will miss.

§8.3 turns "reads the new key at construction" from an expectation into something enforced:
an instance cannot be constructed mid-rotation at all, so the only stores in existence are
ones that resolved their key against a `READY` system.

This is worth stating explicitly because it is a case where the right implementation is the
simple one *given a documented operating assumption*, and looks like an oversight without
it.

---

## 10. Audit log

`system_audit_events` records lifecycle history. The division of labour is:

- the **key table** holds current state;
- the **audit log** holds how it got there.

| Event | Emitted by |
|---|---|
| `SYSTEM_INITIALIZED` | §7.1 |
| `DEK_ROTATION_STARTED` / `DEK_ROTATION_COMPLETED` | §7.2 (a) / (d) |
| `KEK_ROTATION_STARTED` / `KEK_ROTATION_COMPLETED` | §7.3 (a) / (c) |
| `ADD_NEW_ENCRYPTION_KEY` | §7.1, §7.2 (b) |
| `RETIRE_ENCRYPTION_KEY` | §7.2 (b) |
| `DELETE_ENCRYPTION_KEY` | §7.2 (d) |
| `ADD_NEW_RECORD` | `DefineNewRecord` |
| `DELETE_RECORD` | `DeleteRecord` |
| `PURGE_UNDECRYPTABLE_VERSION` | §7.2.1 — one per destroyed version |

`RETIRE_ENCRYPTION_KEY` replaces the old `DEACTIVATE_ENCRYPTION_KEY`.
`ACTIVATE_ENCRYPTION_KEY` and `SYSTEM_INITIALIZING` are removed along with the API and
state that produced them (§6.2, §5.3).

The five lifecycle events in the first three rows are written by the state transition
itself, inside `db`'s `updateSystemParamState`, selected from the `(old state, new state)`
pair. `maintenance` emits none of them directly: writing the event where the transition
happens makes the two atomic, so the log can never disagree with the state.

Metadata shapes are per event type and validated on write; `SystemEventAudit.ParseMetadata`
dispatches on the type to parse them back. Rotation boundary events carry no metadata —
the state they moved between is the whole content.

**Per-row re-encryption is deliberately not audited.** A rotation over a large store would
otherwise write one audit row per version, drowning the log in noise that carries no
information the rotation-completed event does not already imply.

Per-row **destruction** is the opposite case, and is audited individually. Which versions
§7.2.1 destroyed is information no other event implies, and it is the only record that they
ever existed.

---

## 11. Error taxonomy

All error types derive from `goutils.BaseError`, which carries a name, message, wrapped
cause and optional call stack, and implements `Unwrap`. Matching is therefore done with
`errors.As`, and works through arbitrary layers of wrapping:

```go
var notFound goutils.NotFoundError
if errors.As(err, &notFound) { … }
```

| Type | Source | Raised by |
|---|---|---|
| `goutils.SQLError` | goutils | `db` — a failed SQL statement |
| `goutils.NotFoundError` | goutils | `db` — a single-entry fetch found nothing |
| `goutils.ValidationError` | goutils | model validation, certificate rejection |
| `goutils.ConsistencyError` | goutils | illegal state transitions |
| `goutils.RuntimeError` | goutils | wrapping at the `db` API boundary; lifecycle guard rails (§8.1) |
| `goutils.PersistenceError` | goutils | layers wrapping a `db` failure — `store`, `encryption`, `maintenance` |
| `models.EncryptionError` | haven | `encryption` — cryptographic failures |
| `models.KVStoreError` | haven | `store` — the outermost wrap on a KV operation |
| `models.MaintenanceError` | haven | `maintenance` — the outermost wrap on a maintenance action |
| `encryption.UndecryptableVersion` | haven | `encryption` — one record version which will not unseal (§7.2.1) |

`haven` defines only the types goutils has no equivalent for. It previously defined its
own `PersistenceError` and `SQLError`; those were replaced by the goutils types of the same
name.

**Each application-facing layer stamps its own type at its public boundary, and only
there.** `store`, `encryption` and `maintenance` wrap what every exported method returns;
inside — transaction callbacks, step helpers — the goutils type that describes what actually
failed is kept. So the outermost name says which layer was asked to do something, and
everything underneath says why it could not. Nothing is replaced along the way: `errors.As`
still reaches every inner type, which is what makes a three-layer wrap informative rather
than lossy.

The inner wraps earn their place in a multi-step action. "Failed to close the encryption key
rotation" narrows a §7.2 failure to step (d) — the drain finished and the key delete did
not — which is the difference between rerunning the rotation and investigating the data.

`UndecryptableVersion` is the exception to the taxonomy above: it is not a
`goutils.BaseError` but a finding which happens to satisfy `error`, carrying the offending
row and its cause. It is reached with `errors.As` through whatever the caller wrapped it
in, which is what lets `maintenance` tell "this row is corrupt" apart from "the write
failed" — the distinction §7.2.1's whole recovery path turns on.

### 11.1 `notFoundOrError`

Every single-entry fetch in `db` routes its error through one helper
([`db/database.go`](db/database.go)):

```go
func notFoundOrError(err error, entity, id string) error
```

It maps `gorm.ErrRecordNotFound` to a `goutils.NotFoundError` and everything else to a
`goutils.SQLError`, both with a consistent message. Keeping this in one place is what makes
`errors.As(err, &notFound)` reliable at every call site — §9.1 depends on the distinction
being exact.

---

## 12. Persistence and deployment

`haven` speaks to the database through GORM.

**SQLite** backs the tests. [`db.GetSqliteDialector`](db/client.go) appends
`?_foreign_keys=on`, which is required — SQLite does not enforce foreign keys by default,
and without it the `RESTRICT` behaviour §7.2 depends on would silently not apply.

**Postgres** is the production target. The schema is managed by
[Atlas](https://atlasgo.io/) migrations generated *from* the GORM models: `make gen-migrate`
runs `utils/atlas-migrate` to dump the model schema, diffs it against `migrations/`, and
writes a new versioned SQL file. `make dev-migrate` applies them to the local development
Postgres from `docker/docker-compose.yml`.

The model changes this design introduces each need a migration:

- `encryption_keys.kek_id`, `NOT NULL`;
- `encryption_keys.state` and `system_params.state` ENUM value rewrites;
- `record_versions.enc_key_id` from `ON DELETE CASCADE` to `ON DELETE RESTRICT`.

Because no embedding project has reached production, existing development databases are
recreated rather than migrated. A `NOT NULL` `kek_id` on rows whose wrapping KEK is unknown
has no correct backfill value, so this is the only honest option — and it is free while it
lasts.

---

## 13. Testing strategy

| Package | Approach |
|---|---|
| `db` | Real SQLite at `/tmp/haven_ut_<ulid>.db`, fresh per test. No mocks — the behaviour under test *is* the SQL. |
| `store`, `encryption` | mockery mocks of the layer below, under `mocks/` (`make mock`). Lets a test drive error paths a real database will not produce on demand. |
| `maintenance` | Real SQLite — the transaction boundaries and resume rules are the behaviour under test, and a mock cannot exhibit them. |
| end-to-end (`haven_test.go`) | Real SQLite, real cryptography, real certificates. |

x509 fixtures live in `test/certs/` and are generated by `test/gen_certs.py`
(`make gen-test-certs`): a root CA, an intermediate CA, user certificates issued by each,
an already-expired certificate, and an unrelated self-signed certificate. Regenerating them
is deterministic in structure but not in key material.

Three families of test carry the lifecycle work:

- **State machine** — one per legal edge, plus rejection of every illegal edge, plus the
  CAS losing to a concurrent change.
- **Crash resume** — one per transaction boundary in §7.2 and §7.3. Each stages the state a
  crash would leave behind by driving `db` directly, re-enters the action, and asserts it
  finishes the interrupted run rather than starting a new one. The §7.2 (d) atomicity
  argument is only credible because a test covers it: without the entry dispatch, a resumed
  rotation mints a third key, and the test fails on exactly that.
- **Guard rails** — one per guarded method in §8.1, plus the constructor in §8.3, in each
  non-`READY` state.

Three assertions are worth naming because they pin claims made elsewhere in this document
and would otherwise be easy to write in a form that always passes:

- A re-encrypted version must **fail** to decrypt under the associated data of the row it
  came from, not merely succeed under the new one (§4.2).
- A KEK rotation must leave `enc_value`, `enc_nonce` and `enc_key_id` **byte-identical**.
  That is the whole claim of §7.3.
- The §8.3 constructor tests register **no** `NewEncryptionKey` expectation on the mock
  cryptography engine. A store that mints therefore fails them as an unexpected call, which
  is how the removal of minting stays removed.

---

## 14. Implementation status

| Section | Status |
|---|---|
| 1. Motivation and scope | — |
| 2. Architecture | Built |
| 3. Data model | Built |
| 4.1 KEK loading and certificate validation | Built |
| 4.2 Associated data | Built |
| 4.3 DEK cache | Built, including retired keys |
| 4.4 Input guards | Built |
| 4.5 `kek_id` | Built — derived on KEK load, stamped on every key the engine mints |
| 5. System lifecycle | Built, and driven by §7 |
| 6. Encryption key states | Built and enforced — `CanEncrypt`/`CanDecrypt` gate the data path |
| 7. Maintenance actions | Built — `maintenance.Runner`, reached through `haven.NewMaintenanceRunner` |
| 7.2.1 Purge | Built, end to end: halt, `ListUndecryptableVersions`, `PurgeUndecryptableVersions`, resume |
| 7.5 Paging | Built — both rules, each named at its loop |
| 8.1 Guard rails | Built |
| 8.2 Unguarded maintenance write | Built — `db.Database.UpdateRecordVersionEncryption` |
| 8.3 KV store constructor check | Built — `NewProtectedKVStore` checks the state, takes the first `ACTIVE` key, and never mints |
| 9. KV store semantics | Built |
| 10. Audit log | Built |
| 11. Error taxonomy | Built |
| 12. Persistence and deployment | Built; the migration for §3 is not yet generated |
| 13. Testing strategy | Built, including the crash-resume tests for both rotations |

---

## 15. Non-goals and deferred

**Revocation checking.** No CRL or OCSP, now or planned (§4.1).

**A multi-KEK ring.** KEK rotation is an explicit operation over exactly two KEKs, not a
rolling deploy in which instances temporarily accept several. A ring would only be needed
to rotate without downtime, which §7.4 rules out.

**Online rotation.** Both rotations require a maintenance window proportional to the data.
An online design is possible — retire-then-drain with per-row compare-and-swap updates,
which is broadly what §7.2 does, plus a working key resolved per write instead of at
construction — and should be revisited if version counts ever make the window untenable. It
is deliberately not built now: every mechanism it needs exists to survive concurrency that
§7.4 removes.

**Write-ahead buffering during rotation.** A service could queue writes and drain them
afterwards. A library cannot, because there is no process guaranteed to be alive to do the
draining.

**Access control and multi-tenancy.** Out of scope permanently (§1.2).

**Exposing `db.Client` from the entry point.** `haven.NewProtectedKVStore` creates the
persistence client internally and does not return it, so an embedding application cannot
obtain a `db.Database` to pass as `activeDBClient` — the composition mechanism in §2.2 is
therefore unreachable from outside. Either returning the client alongside the store or
accepting one as a parameter would fix it. Still open, and unrelated to the lifecycle work.
