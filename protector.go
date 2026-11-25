package privacy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/ln80/privacy-engine/aes"
	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/internal/keyengine"
	sensitive "github.com/ln80/struct-sensitive"
	"golang.org/x/crypto/hkdf"
)

// Errors returned by Protector service
var (
	ErrEncryptDecryptFailure = newErr("failed to encrypt/decrypt")
	ErrForgetSubjectFailure  = newErr("failed to forget subject")
	ErrRecoverSubjectFailure = newErr("failed to recover subject")
	ErrClearCacheFailure     = newErr("failed to clear cache")
	ErrPurgeNamespaceFailure = newErr("failed to purge namespace")
	ErrCannotRecoverSubject  = newErr("cannot recover subject")
	ErrSubjectForgotten      = newErr("subject is forgotten")

	// ErrKeyUnknown means the key engine has no record of the subject in this
	// namespace: never created, purged, or a value from another namespace or a
	// misconfigured backend. Unlike a forgotten subject, the field is not
	// replaced: the call fails and the value is left untouched.
	ErrKeyUnknown = newErr("subject key is unknown in this namespace")

	// ErrValueNotAuthentic means a field holds a value in wire format that
	// does not authenticate under its subject's active key: tampered, forged,
	// or encrypted elsewhere. Encrypt refuses to keep or re-encrypt it.
	ErrValueNotAuthentic = newErr("value looks encrypted but does not authenticate")

	// ErrMultipleSubjects means Encrypt found data of several subjects in
	// one struct, where the Protector allows one (see WithMultipleSubjects).
	ErrMultipleSubjects = sensitive.ErrMultipleSubjectID

	// ErrReservedSubjectID means a subject ID starts with "@". Those IDs name
	// the library's own keys (the vault key is "@vault") and cannot be used to
	// encrypt, forget, recover or derive.
	ErrReservedSubjectID = newErr("subject IDs starting with @ are reserved")
)

// reservedIDPrefix marks IDs that belong to the library, such as vaultKeyID.
const reservedIDPrefix = "@"

func isReservedID(id string) bool {
	return strings.HasPrefix(id, reservedIDPrefix)
}

// checkSubjectID refuses a reserved subject ID.
func checkSubjectID(id string) error {
	if isReservedID(id) {
		return ErrReservedSubjectID
	}
	return nil
}

// protectorConfig is set by ProtectorOption.
type protectorConfig struct {

	// KeyEngine presents an implementation of core.KeyEngine.
	// It manages encryption materials' life-cycle.
	KeyEngine core.KeyEngine

	// Encryptor presents an implementation of core.Encryptor.
	// It allows using a specific encryption algorithm.
	Encryptor core.Encryptor

	// CacheEnabled used to enable/disable cache.
	CacheEnabled bool

	// CacheTTL defines the cache's time to live duration.
	CacheTTL time.Duration

	// GracefulMode disables keys and hides vault entries on Forget, so
	// Recover works until the grace period ends. Otherwise Forget erases at
	// once.
	GracefulMode bool

	// TokenEngine stores the token vault (core.TokenEngine). It is never
	// cached: the vault holds sealed values, and the vault key is cached with
	// the other keys.
	TokenEngine core.TokenEngine

	// MultipleSubjects lets Encrypt accept a struct whose data belongs to
	// several subjects, such as a record with an embedded author that declares
	// its own subjectID. Each field is then encrypted under the nearest
	// declared subject. Off by default: one record, one key to forget.
	// Decrypt reads the subject from each value and accepts either.
	MultipleSubjects bool

	// ForgottenValue replaces a field whose subject is forgotten, when the
	// field's tag has no replace= option. Default "".
	ForgottenValue string

	// Auditor receives an event for every call of Forget, Recover,
	// DeleteToken, Purge, Detokenize, ListTokens and DeriveSubjectKey
	// (docs/audit-events.md). Nil by default: no events.
	Auditor Auditor
}

// subjectKeyVersion is the only DEK version until rotation exists; it is bound
// into every ciphertext so rotation can later tell versions apart.
const subjectKeyVersion uint32 = 1

// Protector encrypts, decrypts and crypto-erases subjects' personal data,
// and tokenizes values. Build it with NewProtector; it is safe for concurrent
// use. Code that needs only part of it can accept one of the role interfaces:
// Encrypter, Shredder, Tokenizer, Reidentifier.
//
// With WithAuditor set, Forget, Recover, DeleteToken, Purge,
// Detokenize, ListTokens and DeriveSubjectKey each emit an AuditEvent. When it
// cannot be recorded, the first four still apply and return ErrAuditFailure;
// the last three return nothing.
type Protector struct {
	namespace string
	cfg       *protectorConfig
}

// NewProtector returns a Protector service instance.
// It requires a Key engine and accepts options to overwrite the default configuration.
//
// It panics if the given engine is nil.
// It uses a default namespace if the given namespace is empty.
//
// By default, Cache and Graceful mode options are enabled and 'AES 256 GCM' Encryptor is used.
func NewProtector(namespace string, engine core.KeyEngine, opts ...ProtectorOption) *Protector {
	if namespace == "" {
		namespace = "default"
	}

	p := &Protector{
		namespace: namespace,
		cfg: &protectorConfig{
			Encryptor:    aes.NewEncryptor(),
			KeyEngine:    engine,
			CacheEnabled: true,
			GracefulMode: true,
		},
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(p.cfg)
	}

	if p.cfg.KeyEngine == nil {
		panic("invalid Key Engine service, nil value found")
	}

	if p.cfg.CacheEnabled {
		if _, ok := p.cfg.KeyEngine.(keyengine.Cache); !ok {
			p.cfg.KeyEngine = keyengine.NewCache(p.cfg.KeyEngine, p.cfg.CacheTTL)
		}
	}

	return p
}

// Encrypt encrypts Personal data fields of the given structs pointers.
// It does its best to ensure atomicity in case of multiple structs pointers.
// It ensures idempotency and only encrypts fields once: a value already in
// wire format is kept only if it authenticates under its own subject's
// active key, or if that subject is forgotten (the value is shredded).
// Any other look-alike value fails with ErrValueNotAuthentic.
//
// Each field is encrypted under its own subject's key. By default a struct
// must use one subject: a second subjectID that governs data, or differing
// subject values, fail with ErrMultipleSubjects. Set
// WithMultipleSubjects to allow several. A subject whose key is
// forgotten fails with ErrSubjectForgotten.
func (p *Protector) Encrypt(ctx context.Context, structPtrs ...any) (err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	mode := sensitive.SingleSubject
	if p.cfg.MultipleSubjects {
		mode = sensitive.MultipleSubjects
	}
	structs := make([]sensitive.Struct, 0)
	subjectIDs := make([]string, 0)
	for _, strPtr := range structPtrs {
		piiStruct, err := sensitive.Scan(strPtr, true, sensitive.WithSubjectMode(mode))
		if err != nil {
			return err
		}

		if piiStruct.HasSensitive() {
			// Every subject the data uses, not only the root's: a nested
			// subject's key would otherwise be missing and read as forgotten.
			subs, err := piiStruct.Subjects()
			if err != nil {
				return err
			}
			structs = append(structs, piiStruct)
			subjectIDs = append(subjectIDs, subs...)
		}
	}
	if len(subjectIDs) == 0 {
		return nil
	}

	slices.Sort(subjectIDs)
	subjectIDs = slices.Compact(subjectIDs)
	for _, id := range subjectIDs {
		if err = checkSubjectID(id); err != nil {
			return err
		}
	}

	// Values already in wire format may name other subjects (a copied value);
	// their keys are needed to authenticate them.
	valueSubjects, err := collectValueSubjects(structs)
	if err != nil {
		return err
	}

	ring, err := p.encryptKeyRing(ctx, subjectIDs, valueSubjects)
	if err != nil {
		return err
	}
	defer zeroKeyMap(ring.keys)

	fn := func(fr sensitive.FieldReplace, val string) (newVal string, err error) {
		newVal = val
		if val == "" {
			return
		}
		// Idempotency: decided by authentication, never by shape.
		if wv, perr := parseWireValue(val); perr == nil {
			err = p.checkEncrypted(fr, wv, ring)
			return
		}

		key, state := ring.lookup(fr.SubjectID)
		if state != core.StateActive {
			err = ErrSubjectForgotten.withSubject(fr.SubjectID)
			return
		}
		encodedVal, err := p.cfg.Encryptor.Encrypt(p.subjectBinding(), key, []byte(val))
		if err != nil {
			return
		}
		newVal = encodeWireValue(wireValue{
			subjectID:  fr.SubjectID,
			alg:        p.cfg.Encryptor.Algorithm(),
			keyVersion: subjectKeyVersion,
			ciphertext: encodedVal,
		})
		return
	}

	for idx, s := range structs {
		if err = s.Replace(fn); err != nil {
			err = fmt.Errorf("%w at #%d", err, idx)
			return
		}
	}
	return
}

// Decrypt decrypts Personal data fields of the given structs pointers.
// Each struct is all-or-nothing. A field that is not in wire format is
// left as is. Each value's own subject selects its key:
//   - active key: the value is decrypted; one that does not authenticate is an error;
//   - disabled or deleted key (forgotten subject): the field gets the tag's
//     replace= option, or WithForgottenValue;
//   - unknown key: ErrKeyUnknown, and the field is left untouched.
func (p *Protector) Decrypt(ctx context.Context, structPtrs ...any) (err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.withBase(err).withNamespace(p.namespace)
		}
	}()

	structs := make([]sensitive.Struct, 0)
	for _, strPtr := range structPtrs {
		piiStruct, err := sensitive.Scan(strPtr, false)
		if err != nil {
			return err
		}
		if piiStruct.HasSensitive() {
			structs = append(structs, piiStruct)
		}
	}
	if len(structs) == 0 {
		return nil
	}

	subjectIDs, err := collectValueSubjects(structs)
	if err != nil {
		return
	}
	keys, states, err := p.cfg.KeyEngine.GetKeys(ctx, p.namespace, subjectIDs)
	if err != nil {
		return
	}
	ring := keyRing{keys: keys, states: states}
	defer zeroKeyMap(ring.keys)

	fn := func(fr sensitive.FieldReplace, val string) (newVal string, err error) {
		newVal = val
		wv, perr := parseWireValue(val)
		if perr != nil {
			// Not a field value: a field that was never encrypted is left as is.
			return
		}

		plain, state, err := p.openValue(fr, wv, ring)
		if err != nil {
			return
		}
		switch state {
		case core.StateActive:
			newVal = string(plain)
			clear(plain)
		case core.StateDisabled, core.StateDeleted:
			newVal = p.forgottenValue(fr)
		default:
			err = fmt.Errorf("%w at %s", ErrKeyUnknown.withSubject(wv.subjectID), fr.Path)
		}
		return
	}

	for idx, s := range structs {
		if err = s.Replace(fn); err != nil {
			err = fmt.Errorf("%w at #%d", err, idx)
			return
		}
	}

	return
}

// EncryptStream reads plaintext from r and returns a reader of ciphertext.
// subID selects the encryption key within the namespace.
func (p *Protector) EncryptStream(ctx context.Context, subID string, r io.Reader) (out io.Reader, err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	if subID == "" {
		return nil, errors.New("empty subject id")
	}
	if err = checkSubjectID(subID); err != nil {
		return nil, err
	}

	keys, err := p.cfg.KeyEngine.GetOrCreateKeys(ctx, p.namespace, []string{subID}, p.cfg.Encryptor.KeyGen())
	if err != nil {
		return nil, err
	}
	defer zeroKeyMap(keys)

	key, ok := keys[subID]
	if !ok {
		return nil, ErrSubjectForgotten.withSubject(subID)
	}

	return p.cfg.Encryptor.EncryptStream(p.subjectBinding(), key, r)
}

// DecryptStream reads ciphertext from r and returns a reader of plaintext.
// subID selects the decryption key within the namespace.
func (p *Protector) DecryptStream(ctx context.Context, subID string, r io.Reader) (out io.Reader, err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	if subID == "" {
		return nil, errors.New("empty subject id")
	}
	if err = checkSubjectID(subID); err != nil {
		return nil, err
	}

	key, err := p.subjectKey(ctx, subID)
	if err != nil {
		return nil, err
	}
	defer core.ZeroKey(key)

	return p.cfg.Encryptor.DecryptStream(p.subjectBinding(), key, r)
}

func (p *Protector) deriveSubjectKey(ctx context.Context, subID, purpose string) (key core.Key, err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	if subID == "" {
		return nil, errors.New("empty subject id")
	}
	if err = checkSubjectID(subID); err != nil {
		return nil, err
	}
	if len(subID) > 1<<16-1 {
		return nil, errors.New("subject id too long")
	}

	parentKey, err := p.subjectKey(ctx, subID)
	if err != nil {
		return nil, err
	}
	defer core.ZeroKey(parentKey)

	info := make([]byte, 2+len(subID)+len(purpose))
	binary.BigEndian.PutUint16(info, uint16(len(subID))) // #nosec G115 -- length validated above
	copy(info[2:], subID)
	copy(info[2+len(subID):], purpose)
	r := hkdf.New(sha256.New, parentKey, []byte("privacy-engine-v1"), info)
	derived := make([]byte, 32)
	if _, err = io.ReadFull(r, derived); err != nil {
		return nil, err
	}
	return core.Key(derived), nil
}

// EncryptStreamWithKey encrypts plaintext from r using the provided key,
// bypassing the KeyEngine lookup.
func (p *Protector) EncryptStreamWithKey(ctx context.Context, key core.Key, r io.Reader) (out io.Reader, err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	return p.cfg.Encryptor.EncryptStream(p.callerKeyBinding(), key, r)
}

// DecryptStreamWithKey decrypts ciphertext from r using the provided key,
// bypassing the KeyEngine lookup.
func (p *Protector) DecryptStreamWithKey(ctx context.Context, key core.Key, r io.Reader) (out io.Reader, err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	return p.cfg.Encryptor.DecryptStream(p.callerKeyBinding(), key, r)
}

// forgetConfig is set by ForgetOption.
type forgetConfig struct {
	// immediate deletes the subject's key material and erases its vault
	// entry at once, whatever the protector's mode. Recover then fails.
	immediate bool
}

// forget implements Protector.Forget and records what it found in ev.
func (p *Protector) forget(ctx context.Context, subID string, cfg forgetConfig, ev *AuditEvent) (err error) {

	defer func() {
		if err != nil {
			err = ErrForgetSubjectFailure.
				withBase(err).
				withNamespace(p.namespace).
				withSubject(subID)
		}
	}()

	if err = checkSubjectID(subID); err != nil {
		return
	}

	graceful := p.cfg.GracefulMode && !cfg.immediate
	ev.Immediate = !graceful

	var keyErr error
	if graceful {
		keyErr = p.cfg.KeyEngine.DisableKey(ctx, p.namespace, subID)
	} else {
		keyErr = p.deleteSubjectKey(ctx, subID)
	}
	if keyErr != nil && !errors.Is(keyErr, core.ErrKeyNotFound) {
		return keyErr
	}
	ev.HadKey = keyErr == nil

	hadEntry, err := p.forgetVaultEntry(ctx, subID, graceful)
	if err != nil {
		return err
	}
	ev.HadToken = hadEntry
	// ErrKeyNotFound only when the ID had neither a key nor a vault entry:
	// a token never used as a subject has only the latter.
	if keyErr != nil && !hadEntry {
		return keyErr
	}
	return nil
}

// deleteSubjectKey deletes the subject's key for an immediate Forget. It
// returns core.ErrKeyNotFound when there was no key to delete (never created,
// purged, or already deleted), as DisableKey does in graceful mode:
// DeleteKey itself succeeds on such IDs and cannot tell.
func (p *Protector) deleteSubjectKey(ctx context.Context, subID string) error {
	_, missing, err := p.cfg.KeyEngine.GetKeys(ctx, p.namespace, []string{subID})
	if err != nil {
		return err
	}
	state, absent := missing[subID]
	if err := p.cfg.KeyEngine.DeleteKey(ctx, p.namespace, subID); err != nil {
		return err
	}
	if absent && state != core.StateDisabled {
		return fmt.Errorf("%w: no key to delete (%s)", core.ErrKeyNotFound, state)
	}
	return nil
}

// forgetVaultEntry applies Forget to the ID's vault entry, if the protector
// has a token engine and the ID is a token. Graceful mode hides the entry and
// removes its index entry, so the value no longer finds the token and the
// same person tokenized again gets a new one; the sealed value
// stays for Recover until the janitor's EraseForgotten. Immediate mode erases
// it at once.
func (p *Protector) forgetVaultEntry(ctx context.Context, token string, graceful bool) (bool, error) {
	if p.cfg.TokenEngine == nil {
		return false, nil
	}
	var err error
	if graceful {
		err = p.cfg.TokenEngine.Forget(ctx, p.namespace, token, time.Now())
	} else {
		err = p.cfg.TokenEngine.Erase(ctx, p.namespace, token)
	}
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, core.ErrTokenNotFound):
		return false, nil
	default:
		return false, err
	}
}

// recoverSubject implements Protector.Recover.
func (p *Protector) recoverSubject(ctx context.Context, subID string) (err error) {
	defer func() {
		if err != nil {
			if errors.Is(err, core.ErrKeyNotFound) {
				err = ErrCannotRecoverSubject.
					withBase(err).
					withNamespace(p.namespace).
					withSubject(subID)
			} else {
				err = ErrRecoverSubjectFailure.
					withBase(err).
					withNamespace(p.namespace).
					withSubject(subID)
			}

		}
	}()

	if err = checkSubjectID(subID); err != nil {
		return
	}

	keyErr := p.cfg.KeyEngine.ReEnableKey(ctx, p.namespace, subID)
	if keyErr != nil && !errors.Is(keyErr, core.ErrKeyNotFound) {
		return keyErr
	}

	restored, err := p.restoreVaultEntry(ctx, subID)
	if err != nil {
		return err
	}
	if keyErr != nil && !restored {
		return keyErr
	}
	return nil
}

// restoreVaultEntry makes a forgotten vault entry active again. Its index entry
// is recreated unless a newer token took the value meanwhile; the old data is
// then recovered and the value stays with the newer token. An
// erased entry cannot come back.
func (p *Protector) restoreVaultEntry(ctx context.Context, token string) (bool, error) {
	if p.cfg.TokenEngine == nil {
		return false, nil
	}
	_, err := p.cfg.TokenEngine.Restore(ctx, p.namespace, token)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, core.ErrTokenNotFound), errors.Is(err, core.ErrTokenErased):
		return false, nil
	default:
		return false, err
	}
}

// keyRing holds the keys fetched for one Encrypt or Decrypt call and the
// state of every subject without an active key.
type keyRing struct {
	keys   core.KeyMap
	states core.KeyStates
}

// lookup returns the subject's active key, or its state. A subject the
// engine said nothing about is unknown.
func (r keyRing) lookup(subjectID string) (core.Key, core.KeyState) {
	if k, ok := r.keys[subjectID]; ok {
		return k, core.StateActive
	}
	if st, ok := r.states[subjectID]; ok {
		return nil, st
	}
	return nil, core.StateUnknown
}

// encryptKeyRing gets or creates the keys of the struct subjects, and only
// reads the keys of other subjects named by values already in wire format.
func (p *Protector) encryptKeyRing(ctx context.Context, structSubjects, valueSubjects []string) (keyRing, error) {
	keys, err := p.cfg.KeyEngine.GetOrCreateKeys(ctx, p.namespace, structSubjects, p.cfg.Encryptor.KeyGen())
	if err != nil {
		return keyRing{}, err
	}
	ring := keyRing{keys: keys, states: core.KeyStates{}}
	// GetOrCreateKeys creates unknown subjects, so a struct subject it did not
	// return is disabled or deleted: forgotten.
	for _, id := range structSubjects {
		if _, ok := keys[id]; !ok {
			ring.states[id] = core.StateDisabled
		}
	}

	others := make([]string, 0, len(valueSubjects))
	for _, id := range valueSubjects {
		if !slices.Contains(structSubjects, id) {
			others = append(others, id)
		}
	}
	if len(others) == 0 {
		return ring, nil
	}
	otherKeys, states, err := p.cfg.KeyEngine.GetKeys(ctx, p.namespace, others)
	if err != nil {
		zeroKeyMap(keys)
		return keyRing{}, err
	}
	for id, k := range otherKeys {
		ring.keys[id] = k
	}
	for id, st := range states {
		ring.states[id] = st
	}
	return ring, nil
}

// collectValueSubjects returns, sorted and unique, the subjects named by
// field values already in wire format. It does not change the structs.
func collectValueSubjects(structs []sensitive.Struct) ([]string, error) {
	subjects := make([]string, 0)
	collect := func(_ sensitive.FieldReplace, val string) (string, error) {
		// A reserved subject is never fetched: openValue refuses it.
		if wv, err := parseWireValue(val); err == nil && !isReservedID(wv.subjectID) {
			subjects = append(subjects, wv.subjectID)
		}
		return val, nil
	}
	for idx, s := range structs {
		if err := s.Replace(collect); err != nil {
			return nil, fmt.Errorf("%w at #%d", err, idx)
		}
	}
	slices.Sort(subjects)
	return slices.Compact(subjects), nil
}

// openValue checks a parsed value's header and, when its subject's key is
// active, decrypts it. It returns the subject's key state; plaintext is set
// only for StateActive. A value that does not authenticate is an error.
func (p *Protector) openValue(fr sensitive.FieldReplace, wv wireValue, ring keyRing) (plain []byte, state core.KeyState, err error) {
	// Checked before the key lookup: a value this protector cannot read is an
	// error whatever its subject's state.
	if wv.alg != p.cfg.Encryptor.Algorithm() {
		return nil, "", fmt.Errorf("%w: unsupported algorithm %#x at %s", ErrInvalidWireFormat, wv.alg, fr.Path)
	}
	if wv.keyVersion != subjectKeyVersion {
		return nil, "", fmt.Errorf("%w: unsupported key version %d at %s", ErrInvalidWireFormat, wv.keyVersion, fr.Path)
	}
	if isReservedID(wv.subjectID) {
		return nil, "", fmt.Errorf("%w at %s", ErrReservedSubjectID, fr.Path)
	}

	key, state := ring.lookup(wv.subjectID)
	if state != core.StateActive {
		return nil, state, nil
	}
	plain, err = p.cfg.Encryptor.Decrypt(p.subjectBinding(), key, wv.ciphertext)
	if err != nil {
		return nil, state, fmt.Errorf("%w at %s", err, fr.Path)
	}
	return plain, state, nil
}

// checkEncrypted decides whether Encrypt may keep a value already in wire
// format:
//   - active key and it authenticates: keep;
//   - forgotten subject: keep, it is a shredded value;
//   - anything else: error, never re-encrypt a look-alike.
func (p *Protector) checkEncrypted(fr sensitive.FieldReplace, wv wireValue, ring keyRing) error {
	plain, state, err := p.openValue(fr, wv, ring)
	clear(plain)
	switch {
	case err != nil:
		return fmt.Errorf("%w: %w", ErrValueNotAuthentic, err)
	case state == core.StateActive, state == core.StateDisabled, state == core.StateDeleted:
		return nil
	default:
		return fmt.Errorf("%w at %s", ErrKeyUnknown.withSubject(wv.subjectID), fr.Path)
	}
}

// forgottenValue is the placeholder for a field whose subject is forgotten.
func (p *Protector) forgottenValue(fr sensitive.FieldReplace) string {
	if v, ok := fr.Options["replace"]; ok {
		return v
	}
	return p.cfg.ForgottenValue
}

// subjectKey returns the subject's active key for the stream and derivation
// methods: ErrSubjectForgotten if it is disabled or deleted, ErrKeyUnknown
// if the engine has no record of it.
func (p *Protector) subjectKey(ctx context.Context, subID string) (core.Key, error) {
	keys, states, err := p.cfg.KeyEngine.GetKeys(ctx, p.namespace, []string{subID})
	if err != nil {
		return nil, err
	}
	key, state := keyRing{keys: keys, states: states}.lookup(subID)
	switch state {
	case core.StateActive:
		return key, nil
	case core.StateDisabled, core.StateDeleted:
		return nil, ErrSubjectForgotten.withSubject(subID)
	default:
		return nil, ErrKeyUnknown.withSubject(subID)
	}
}

// subjectBinding binds data encrypted under a subject's DEK.
func (p *Protector) subjectBinding() core.Binding {
	return core.Binding{Namespace: p.namespace, KeyVersion: subjectKeyVersion}
}

// callerKeyBinding binds data encrypted under a key the caller manages
// (the *WithKey stream methods), which has no version in the key engine.
func (p *Protector) callerKeyBinding() core.Binding {
	return core.Binding{Namespace: p.namespace}
}

// zeroKeyMap wipes key copies this protector owns.
// EncryptStream and DecryptStream expand the key into the AES schedule before returning,
// so wiping the copy when the method returns does not affect an in-flight stream.
func zeroKeyMap(keys core.KeyMap) {
	for id, k := range keys {
		core.ZeroKey(k)
		keys[id] = nil
	}
}

// Clear clears encryption materials' cache based on cache-related configuration.
func (p *Protector) Clear(ctx context.Context, force bool) (err error) {
	defer func() {
		if err != nil {
			err = ErrClearCacheFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	if cp, ok := p.cfg.KeyEngine.(keyengine.Cache); ok {
		if e := cp.ClearCache(ctx, p.namespace, force); e != nil {
			err = e
		}
	}

	return
}

// purge implements Protector.Purge.
func (p *Protector) purge(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			err = ErrPurgeNamespaceFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	if err = p.cfg.KeyEngine.PurgeNamespace(ctx, p.namespace); err != nil {
		return
	}

	if p.cfg.TokenEngine != nil {
		if err = p.cfg.TokenEngine.PurgeNamespace(ctx, p.namespace); err != nil {
			return
		}
	}

	return p.Clear(ctx, true)
}
