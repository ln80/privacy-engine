package privacy

import (
	"context"
	"sync"
	"time"
)

// FactoryClearFunc presents the function returned by Factory.Instance method.
// It tells the associated Protector instance to immediately clear the cache of encryption materials.
type FactoryClearFunc func()

// FactoryNewFunc is used by the Factory service to create Protector instance per namespace.
type FactoryNewFunc func(namespace string) Protector

// Factory manages and maintains a registry of Protector services.
//
// It monitors each Protector service to track its activity
// and regularly clears encryption materials caches.
type Factory interface {

	// Instance creates a new Protector instance for the given namespace or returns the existing one.
	Instance(namespace string) (Protector, FactoryClearFunc)

	// Monitor starts a long-running process in a separate Goroutine.
	// It checks Protectors' activities and removes inactive ones,
	// and clears their caches based on their cache TTL config.
	Monitor(ctx context.Context)
}

// FactoryConfig presents the configuration of Factory service
type FactoryConfig struct {

	// IDLE is the duration used to define whether a Protector service is inactive.
	IDLE time.Duration

	// MonitorPeriod is the frequency of the regular checks made by the monitoring process.
	MonitorPeriod time.Duration
}

type registryEntry struct {
	protector  Protector
	lastUsedAt time.Time
}

type factory struct {
	mu           sync.RWMutex
	reg          map[string]*registryEntry
	newProtector FactoryNewFunc
	*FactoryConfig
}

// NewFactory returns a thread-safe factory service instance.
// It panics if builderFunc is nil.
// Options params allow overwriting the default configuration.
func NewFactory(newProt FactoryNewFunc, opts ...func(*FactoryConfig)) Factory {
	if newProt == nil {
		panic("invalid new Protector func, nil value found")
	}

	f := &factory{
		reg:          make(map[string]*registryEntry),
		newProtector: newProt,
		FactoryConfig: &FactoryConfig{
			IDLE:          20 * time.Minute,
			MonitorPeriod: 5 * time.Second,
		},
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(f.FactoryConfig)
	}

	return f
}

// Instance implements Factory interface
func (f *factory) Instance(namespace string) (Protector, FactoryClearFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()

	entry, ok := f.reg[namespace]
	if !ok {
		entry = &registryEntry{
			protector:  f.newProtector(namespace),
			lastUsedAt: time.Now(),
		}
		f.reg[namespace] = entry
	}
	entry.lastUsedAt = time.Now()

	clearFunc := func() {
		_ = f.reg[namespace].protector.Clear(context.Background(), true)
	}

	return entry.protector, clearFunc
}

func (f *factory) clear(ctx context.Context, force bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for nspace, entry := range f.reg {
		_ = entry.protector.Clear(ctx, force)

		if force || (!entry.lastUsedAt.IsZero() && entry.lastUsedAt.Add(f.IDLE).Before(time.Now())) {
			delete(f.reg, nspace)
		}
	}
}

// Monitor implements Factory interface
func (f *factory) Monitor(ctx context.Context) {
	ticker := time.NewTicker(f.MonitorPeriod)
	go func() {
		defer func() {
			clearCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			f.clear(clearCtx, true)
			cancel()
		}()

		for {
			select {
			case <-ctx.Done():
				return

			case <-ticker.C:
				f.clear(ctx, false)
			}
		}
	}()
}
