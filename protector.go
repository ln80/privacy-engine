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
	"github.com/ln80/privacy-engine/memory"
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

// Protector presents the service's interface that encrypts, decrypts,
// and crypto-erases subjects' Personal data.
type Protector interface {

	// Encrypt encrypts Personal data fields of the given structs pointers.
	// It does its best to ensure atomicity in case of multiple structs pointers.
	// It ensures idempotency and only encrypts fields once: a value already in
	// wire format is kept only if it authenticates under its own subject's
	// active key, or if that subject is forgotten (the value is shredded).
	// Any other look-alike value fails with ErrValueNotAuthentic.
	//
	// Each field is encrypted under its own subject's key. By default a struct
	// must use one subject: a second subjectID that governs data, or differing
	// subject values, fail with struct-sensitive's ErrMultipleSubjectID. Set
	// ProtectorConfig.MultipleSubjects to allow several. A subject whose key is
	// forgotten fails with ErrSubjectForgotten.
	Encrypt(ctx context.Context, structPts ...any) error

	// Decrypt decrypts Personal data fields of the given structs pointers.
	// Each struct is all-or-nothing. A field that is not in wire format is
	// left as is. Each value's own subject selects its key:
	//   - active key: the value is decrypted; one that does not authenticate is an error;
	//   - disabled or deleted key (forgotten subject): the field gets the tag's
	//     replace= option, or ProtectorConfig.ForgottenValue;
	//   - unknown key: ErrKeyUnknown, and the field is left untouched.
	Decrypt(ctx context.Context, structPts ...any) error

	// EncryptStream reads plaintext from r and returns a reader of ciphertext.
	// subID selects the encryption key within the namespace.
	EncryptStream(ctx context.Context, subID string, r io.Reader) (io.Reader, error)

	// DecryptStream reads ciphertext from r and returns a reader of plaintext.
	// subID selects the decryption key within the namespace.
	DecryptStream(ctx context.Context, subID string, r io.Reader) (io.Reader, error)

	// DeriveSubjectKey derives a purpose-scoped key from the subject's DEK without exposing it.
	// purpose is mixed into the derivation (e.g. a client ref hash for attachments).
	DeriveSubjectKey(ctx context.Context, subID, purpose string) (core.Key, error)

	// EncryptStreamWithKey encrypts plaintext from r using the provided key,
	// bypassing the KeyEngine lookup.
	EncryptStreamWithKey(ctx context.Context, key core.Key, r io.Reader) (io.Reader, error)

	// DecryptStreamWithKey decrypts ciphertext from r using the provided key,
	// bypassing the KeyEngine lookup.
	DecryptStreamWithKey(ctx context.Context, key core.Key, r io.Reader) (io.Reader, error)

	// Forget removes the associated encryption materials of the given subject,
	// and crypto-erases its Personal data.
	Forget(ctx context.Context, subID string) error

	// Recover allows to recover encryption materials of the given subject.
	//
	// It fails if the grace period was exceeded, and encryption materials were hard deleted.
	Recover(ctx context.Context, subID string) error

	// Clear clears encryption materials' cache based on cache-related configuration.
	Clear(ctx context.Context, force bool) error

	// Tokenize tokenizes the given values.
	Tokenize(ctx context.Context, values []core.TokenData, opts ...func(*core.TokenizeConfig)) (core.ValueTokenMap, error)

	// Detokenize detokenizes the given tokens.
	Detokenize(ctx context.Context, tokens []string) (core.TokenValueMap, error)

	// DeleteToken deletes the given token.
	DeleteToken(ctx context.Context, token string) error

	// ListTokens lists the tokens.
	ListTokens(ctx context.Context, query core.ListTokensQuery) (result *core.ListTokensResult, err error)

	// Purge hard-deletes every encryption key and token in the protector's
	// namespace, then clears caches. Idempotent.
	Purge(ctx context.Context) error
}

// ProtectorConfig presents the configuration of Protector service
type ProtectorConfig struct {

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

	// GracefulMode allows first to disable the encryption materials during a graceful period.
	// Therefore recovery may succeed. Otherwise, encryption materials are immediately deleted.
	GracefulMode bool

	// TokenEngine is an implementation of core.TokenEngine
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
}

// subjectKeyVersion is the only DEK version until rotation exists; it is bound
// into every ciphertext so rotation can later tell versions apart.
const subjectKeyVersion uint32 = 1

type protector struct {
	namespace string

	*ProtectorConfig
}

var _ Protector = &protector{}

// NewProtector returns a Protector service instance.
// It requires a Key engine and accepts options to overwrite the default configuration.
//
// It panics if the given engine is nil.
// It uses a default namespace if the given namespace is empty.
//
// By default, Cache and Graceful mode options are enabled and 'AES 256 GCM' Encryptor is used.
func NewProtector(namespace string, engine core.KeyEngine, opts ...func(*ProtectorConfig)) Protector {
	if namespace == "" {
		namespace = "default"
	}

	p := &protector{
		namespace: namespace,
		ProtectorConfig: &ProtectorConfig{
			Encryptor:    aes.New256GCMEncryptor(),
			KeyEngine:    engine,
			CacheEnabled: true,
			GracefulMode: true,
		},
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(p.ProtectorConfig)
	}

	if p.KeyEngine == nil {
		panic("invalid Key Engine service, nil value found")
	}

	if p.CacheEnabled {
		if _, ok := p.KeyEngine.(core.KeyEngineCache); !ok {
			p.KeyEngine = memory.NewCacheWrapper(p.KeyEngine, p.CacheTTL)
		}
		if p.TokenEngine != nil {
			if _, ok := p.TokenEngine.(core.TokenEngineCache); !ok {
				p.TokenEngine = memory.NewTokenCacheWrapper(p.TokenEngine, p.CacheTTL)
			}
		}
	}

	return p
}

func (p *protector) Encrypt(ctx context.Context, structPtrs ...any) (err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	mode := sensitive.SingleSubject
	if p.MultipleSubjects {
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
		// Idempotency (PE-05): decided by authentication, never by shape.
		if wv, perr := parseWireValue(val); perr == nil {
			err = p.checkEncrypted(fr, wv, ring)
			return
		}

		key, state := ring.lookup(fr.SubjectID)
		if state != core.StateActive {
			err = ErrSubjectForgotten.withSubject(fr.SubjectID)
			return
		}
		encodedVal, err := p.Encryptor.Encrypt(p.subjectBinding(), key, []byte(val))
		if err != nil {
			return
		}
		newVal = encodeWireValue(wireValue{
			subjectID:  fr.SubjectID,
			alg:        p.Encryptor.Algorithm(),
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

func (p *protector) Decrypt(ctx context.Context, structPtrs ...any) (err error) {
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
	keys, states, err := p.KeyEngine.GetKeys(ctx, p.namespace, subjectIDs)
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

func (p *protector) EncryptStream(ctx context.Context, subID string, r io.Reader) (out io.Reader, err error) {
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

	keys, err := p.KeyEngine.GetOrCreateKeys(ctx, p.namespace, []string{subID}, p.Encryptor.KeyGen())
	if err != nil {
		return nil, err
	}
	defer zeroKeyMap(keys)

	key, ok := keys[subID]
	if !ok {
		return nil, ErrSubjectForgotten.withSubject(subID)
	}

	return p.Encryptor.EncryptStream(p.subjectBinding(), key, r)
}

func (p *protector) DecryptStream(ctx context.Context, subID string, r io.Reader) (out io.Reader, err error) {
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

	return p.Encryptor.DecryptStream(p.subjectBinding(), key, r)
}

func (p *protector) DeriveSubjectKey(ctx context.Context, subID, purpose string) (key core.Key, err error) {
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

func (p *protector) EncryptStreamWithKey(ctx context.Context, key core.Key, r io.Reader) (out io.Reader, err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	return p.Encryptor.EncryptStream(p.callerKeyBinding(), key, r)
}

func (p *protector) DecryptStreamWithKey(ctx context.Context, key core.Key, r io.Reader) (out io.Reader, err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	return p.Encryptor.DecryptStream(p.callerKeyBinding(), key, r)
}

// Forget implements Protector.
func (p *protector) Forget(ctx context.Context, subID string) (err error) {

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

	if p.GracefulMode {
		err = p.KeyEngine.DisableKey(ctx, p.namespace, subID)
		return
	}

	err = p.KeyEngine.DeleteKey(ctx, p.namespace, subID)
	return
}

// Recover implements Protector.
func (p *protector) Recover(ctx context.Context, subID string) (err error) {
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

	err = p.KeyEngine.ReEnableKey(ctx, p.namespace, subID)
	return
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
func (p *protector) encryptKeyRing(ctx context.Context, structSubjects, valueSubjects []string) (keyRing, error) {
	keys, err := p.KeyEngine.GetOrCreateKeys(ctx, p.namespace, structSubjects, p.Encryptor.KeyGen())
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
	otherKeys, states, err := p.KeyEngine.GetKeys(ctx, p.namespace, others)
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
func (p *protector) openValue(fr sensitive.FieldReplace, wv wireValue, ring keyRing) (plain []byte, state core.KeyState, err error) {
	// Checked before the key lookup: a value this protector cannot read is an
	// error whatever its subject's state.
	if wv.alg != p.Encryptor.Algorithm() {
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
	plain, err = p.Encryptor.Decrypt(p.subjectBinding(), key, wv.ciphertext)
	if err != nil {
		return nil, state, fmt.Errorf("%w at %s", err, fr.Path)
	}
	return plain, state, nil
}

// checkEncrypted decides whether Encrypt may keep a value already in wire
// format (PE-05, decision D-C):
//   - active key and it authenticates: keep;
//   - forgotten subject: keep, it is a shredded value;
//   - anything else: error, never re-encrypt a look-alike.
func (p *protector) checkEncrypted(fr sensitive.FieldReplace, wv wireValue, ring keyRing) error {
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
func (p *protector) forgottenValue(fr sensitive.FieldReplace) string {
	if v, ok := fr.Options["replace"]; ok {
		return v
	}
	return p.ForgottenValue
}

// subjectKey returns the subject's active key for the stream and derivation
// methods: ErrSubjectForgotten if it is disabled or deleted, ErrKeyUnknown
// if the engine has no record of it.
func (p *protector) subjectKey(ctx context.Context, subID string) (core.Key, error) {
	keys, states, err := p.KeyEngine.GetKeys(ctx, p.namespace, []string{subID})
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
func (p *protector) subjectBinding() core.Binding {
	return core.Binding{Namespace: p.namespace, KeyVersion: subjectKeyVersion}
}

// callerKeyBinding binds data encrypted under a key the caller manages
// (the *WithKey stream methods), which has no version in the key engine.
func (p *protector) callerKeyBinding() core.Binding {
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

// Clear implements Protector.
func (p *protector) Clear(ctx context.Context, force bool) (err error) {
	defer func() {
		if err != nil {
			err = ErrClearCacheFailure.
				withBase(err).
				withNamespace(p.namespace).
				withSubject(p.namespace)
		}
	}()

	if cp, ok := p.KeyEngine.(core.KeyEngineCache); ok {
		if e := cp.ClearCache(ctx, p.namespace, force); e != nil {
			err = e
		}
	}

	if cp, ok := p.TokenEngine.(core.TokenEngineCache); ok {
		if e := cp.ClearCache(ctx, p.namespace, force); e != nil {
			err = errors.Join(err, e)
		}
	}

	return
}

// Detokenize implements Protector.
func (p *protector) Detokenize(ctx context.Context, tokens []string) (core.TokenValueMap, error) {
	if p.TokenEngine == nil {
		return nil, core.ErrTokenEngineNotConfigured
	}
	return p.TokenEngine.Detokenize(ctx, p.namespace, tokens)
}

// Tokenize implements Protector.
func (p *protector) Tokenize(ctx context.Context, values []core.TokenData, opts ...func(*core.TokenizeConfig)) (core.ValueTokenMap, error) {
	if p.TokenEngine == nil {
		return nil, core.ErrTokenEngineNotConfigured
	}
	return p.TokenEngine.Tokenize(ctx, p.namespace, values, opts...)
}

func (p *protector) DeleteToken(ctx context.Context, token string) error {
	if p.TokenEngine == nil {
		return core.ErrTokenEngineNotConfigured
	}
	return p.TokenEngine.DeleteToken(ctx, p.namespace, token)
}

// ListTokens implements Protector.
func (p *protector) ListTokens(ctx context.Context, query core.ListTokensQuery) (result *core.ListTokensResult, err error) {
	if p.TokenEngine == nil {
		return nil, core.ErrTokenEngineNotConfigured
	}
	return p.TokenEngine.ListTokens(ctx, p.namespace, query)
}

// Purge implements Protector.
func (p *protector) Purge(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			err = ErrPurgeNamespaceFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	if err = p.KeyEngine.PurgeNamespace(ctx, p.namespace); err != nil {
		return
	}

	if p.TokenEngine != nil {
		if err = p.TokenEngine.PurgeNamespace(ctx, p.namespace); err != nil {
			return
		}
	}

	return p.Clear(ctx, true)
}
