package privacy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
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
	ErrCannotRecoverSubject  = newErr("cannot recover subject")
	ErrSubjectForgotten      = newErr("subject is forgotten")
)

// Protector presents the service's interface that encrypts, decrypts,
// and crypto-erases subjects' Personal data.
type Protector interface {

	// Encrypt encrypts Personal data fields of the given structs pointers.
	// It does its best to ensure atomicity in case of multiple structs pointers.
	// It ensures idempotency and only encrypts fields once.
	Encrypt(ctx context.Context, structPts ...any) error

	// Decrypt decrypts Personal data fields of the given structs pointers.
	// It does its best to ensure in case of multiple structs pointers.
	// It ensures idempotency and only decrypts fields once.
	//
	// It replaces the field value with a replacement message, defined in the tag,
	// if the subject is forgotten. Otherwise, the field will be kept empty.
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
}

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

	structs := make([]sensitive.Struct, 0)
	subjectIDs := make([]string, 0)
	for _, strPtr := range structPtrs {
		piiStruct, err := sensitive.Scan(strPtr, true)
		if err != nil {
			return err
		}

		if piiStruct.HasSensitive() {
			structs = append(structs, piiStruct)
			subjectIDs = append(subjectIDs, piiStruct.SubjectID())
		}
	}
	if len(structs) == 0 {
		return nil
	}

	slices.Sort(subjectIDs)
	subjectIDs = slices.Compact(subjectIDs)

	keys, err := p.KeyEngine.GetOrCreateKeys(ctx, p.namespace, subjectIDs, p.Encryptor.KeyGen())
	if err != nil {
		return err
	}

	fn := func(fr sensitive.FieldReplace, val string) (newVal string, err error) {
		key, ok := keys[fr.SubjectID]
		if !ok {
			err = ErrSubjectForgotten.withSubject(fr.SubjectID)
			return
		}
		// idempotency: no need to re-encrypt field value if it's wire formatted.
		// wire formatted implies, it's already encrypted
		if isWireFormatted(val) {
			newVal = val
			return
		}

		encodedVal, err := p.Encryptor.Encrypt(p.namespace, key, val)
		if err != nil {
			return
		}
		newVal = wireFormat(fr.SubjectID, encodedVal)
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

	subjectIDs := make([]string, 0)
	fn := func(fr sensitive.FieldReplace, val string) (newVal string, err error) {
		newVal = val
		_, subjectID, _, err := parseWireFormat(val)
		if err != nil {
			err = nil
			return
		}
		subjectIDs = append(subjectIDs, subjectID)
		return
	}
	for idx, s := range structs {
		if err = s.Replace(fn); err != nil {
			err = fmt.Errorf("%w at #%d", err, idx)
			return
		}
	}
	slices.Sort(subjectIDs)
	subjectIDs = slices.Compact(subjectIDs)
	keys, err := p.KeyEngine.GetKeys(ctx, p.namespace, subjectIDs)
	if err != nil {
		return
	}

	fn = func(fr sensitive.FieldReplace, val string) (newVal string, err error) {
		v, subjectID, cipherText, err := parseWireFormat(val)
		if err != nil {
			// TBD warning ??
			newVal = val
			err = nil
			return
		}
		if v != 1 {
			err = errors.New("unsupported wire format version")
			return
		}

		key, ok := keys[subjectID]
		if !ok {
			newVal = fr.Options["replace"]
			return
		}

		newVal, err = p.Encryptor.Decrypt(p.namespace, key, cipherText)
		if err != nil {
			return "", err
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

	keys, err := p.KeyEngine.GetOrCreateKeys(ctx, p.namespace, []string{subID}, p.Encryptor.KeyGen())
	if err != nil {
		return nil, err
	}

	key, ok := keys[subID]
	if !ok {
		return nil, ErrSubjectForgotten.withSubject(subID)
	}

	return p.Encryptor.EncryptStream(p.namespace, key, r)
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

	keys, err := p.KeyEngine.GetKeys(ctx, p.namespace, []string{subID})
	if err != nil {
		return nil, err
	}

	key, ok := keys[subID]
	if !ok {
		return nil, ErrSubjectForgotten.withSubject(subID)
	}

	return p.Encryptor.DecryptStream(p.namespace, key, r)
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

	keys, err := p.KeyEngine.GetKeys(ctx, p.namespace, []string{subID})
	if err != nil {
		return nil, err
	}

	parentKey, ok := keys[subID]
	if !ok {
		return nil, ErrSubjectForgotten.withSubject(subID)
	}

	info := make([]byte, 2+len(subID)+len(purpose))
	binary.BigEndian.PutUint16(info, uint16(len(subID)))
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

	return p.Encryptor.EncryptStream(p.namespace, key, r)
}

func (p *protector) DecryptStreamWithKey(ctx context.Context, key core.Key, r io.Reader) (out io.Reader, err error) {
	defer func() {
		if err != nil {
			err = ErrEncryptDecryptFailure.
				withBase(err).
				withNamespace(p.namespace)
		}
	}()

	return p.Encryptor.DecryptStream(p.namespace, key, r)
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

	err = p.KeyEngine.ReEnableKey(ctx, p.namespace, subID)
	return
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
