package privacytest

import (
	"bytes"
	"context"
	"sync"

	"github.com/ln80/privacy-engine/core"
)

type KeyEngineMock struct {
	NamespaceList []string
	KeyList       core.KeyMap

	ListNamespaceErr error
	GetKeyErr        error
	CreateKeyErr     error
	ReEnableKeyErr   error
	DeleteKeyErr     error
	DisableKeyErr    error

	mu sync.RWMutex
}

// DeleteKey implements dynamodb.KeyEngine
func (e *KeyEngineMock) DeleteKey(ctx context.Context, namespace string, keyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.DeleteKeyErr; err != nil {
		return err
	}
	return nil
}

// DeleteUnusedKeys implements dynamodb.KeyEngine
func (e *KeyEngineMock) DeleteUnusedKeys(ctx context.Context, namespace string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.DeleteKeyErr; err != nil {
		return err
	}
	return nil
}

// DisableKey implements dynamodb.KeyEngine
func (e *KeyEngineMock) DisableKey(ctx context.Context, namespace string, keyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.DisableKeyErr; err != nil {
		return err
	}

	return nil
}

// GetKeys implements dynamodb.KeyEngine
func (e *KeyEngineMock) GetKeys(ctx context.Context, namespace string, keyIDs []string) (keys core.KeyMap, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.GetKeyErr; err != nil {
		return nil, err
	}

	return cloneKeyMap(e.KeyList), nil
}

// GetOrCreateKeys implements dynamodb.KeyEngine
func (e *KeyEngineMock) GetOrCreateKeys(ctx context.Context, namespace string, keyIDs []string, keyGen core.KeyGen) (core.KeyMap, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.GetKeyErr; err != nil {
		return nil, err
	}

	if err := e.CreateKeyErr; err != nil {
		return nil, err
	}

	return cloneKeyMap(e.KeyList), nil
}

func cloneKeyMap(in core.KeyMap) core.KeyMap {
	if in == nil {
		return nil
	}
	out := core.NewKeyMap()
	for id, k := range in {
		out[id] = bytes.Clone(k)
	}
	return out
}

// ReEnableKey implements dynamodb.KeyEngine
func (e *KeyEngineMock) ReEnableKey(ctx context.Context, namespace string, keyID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.ReEnableKeyErr; err != nil {
		return err
	}
	return nil
}

// ListNamespace implements dynamodb.KeyEngine
func (e *KeyEngineMock) ListNamespace(ctx context.Context) ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.ListNamespaceErr; err != nil {
		return nil, err
	}

	return e.NamespaceList, nil
}

// PurgeNamespace implements core.KeyEngine
func (e *KeyEngineMock) PurgeNamespace(ctx context.Context, namespace string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.DeleteKeyErr; err != nil {
		return err
	}
	e.KeyList = core.NewKeyMap()
	return nil
}

var _ core.KeyEngine = &KeyEngineMock{}
