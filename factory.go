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
type FactoryNewFunc func(namespace string) *Protector

// FactoryConfig presents the configuration of Factory service
type FactoryConfig struct {

	// IDLE is the duration used to define whether a Protector service is inactive.
	IDLE time.Duration

	// MonitorPeriod is the frequency of the regular checks made by the monitoring process.
	MonitorPeriod time.Duration
}

type registryEntry struct {
	protector  *Protector
	lastUsedAt time.Time
}

// Factory keeps one Protector per namespace (tenant). It is safe for
// concurrent use. Monitor evicts idle Protectors and clears expired cache
// entries; build it with NewFactory.
type Factory struct {
	mu           sync.RWMutex
	reg          map[string]*registryEntry
	newProtector FactoryNewFunc
	*FactoryConfig
}

// NewFactory returns a thread-safe factory service instance.
// It panics if builderFunc is nil.
// Options params allow overwriting the default configuration.
func NewFactory(newProt FactoryNewFunc, opts ...FactoryOption) *Factory {
	if newProt == nil {
		panic("invalid new Protector func, nil value found")
	}

	f := &Factory{
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

// Instance returns the Protector of namespace, creating it on first use, and
// a function that clears that Protector's key cache at once.
func (f *Factory) Instance(namespace string) (*Protector, FactoryClearFunc) {
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

	// The clear func keeps the protector it was handed out with. It must not
	// read the registry: Monitor may have evicted the entry by the time it runs
	// (a nil dereference), and the read would race with the map.
	// Clearing an evicted protector is harmless: it only wipes its own cache.
	prot := entry.protector
	clearFunc := func() {
		_ = prot.Clear(context.Background(), true)
	}

	return prot, clearFunc
}

func (f *Factory) clear(ctx context.Context, force bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for nspace, entry := range f.reg {
		_ = entry.protector.Clear(ctx, force)

		if force || (!entry.lastUsedAt.IsZero() && entry.lastUsedAt.Add(f.IDLE).Before(time.Now())) {
			delete(f.reg, nspace)
		}
	}
}

// Monitor starts a goroutine that, every monitor period, clears expired cache
// entries and evicts Protectors idle longer than the idle timeout. When ctx
// ends it clears every cache and stops. Call it once.
func (f *Factory) Monitor(ctx context.Context) {
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
