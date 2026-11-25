package privacy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

// spyCache is a key engine cache that counts ClearCache calls: Protector.Clear
// ends there, so it shows when the factory clears a protector.
type spyCache struct {
	core.KeyEngineCache

	mu     sync.Mutex
	clears int
}

func newSpyCache() *spyCache {
	return &spyCache{KeyEngineCache: memory.NewCacheWrapper(memory.NewKeyEngine(), time.Nanosecond).(core.KeyEngineCache)}
}

func (s *spyCache) ClearCache(ctx context.Context, namespace string, force bool) error {
	s.mu.Lock()
	s.clears++
	s.mu.Unlock()
	return s.KeyEngineCache.ClearCache(ctx, namespace, force)
}

func (s *spyCache) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clears
}

// eventually polls cond until it holds or within elapses. Timing tests wait
// for the state they assert instead of sleeping a fixed time, which failed
// under load when the monitor's ticker fired late.
func eventually(t *testing.T, within time.Duration, cond func() bool, format string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf(format, args...)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestFactory(t *testing.T) {
	protectorCount := func(f *Factory) int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.reg)
	}
	var spiesMu sync.Mutex
	spies := map[string]*spyCache{}
	spyOf := func(namespace string) *spyCache {
		spiesMu.Lock()
		defer spiesMu.Unlock()
		return spies[namespace]
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	builder := func(namespace string) *Protector {
		spy := newSpyCache()
		spiesMu.Lock()
		spies[namespace] = spy
		spiesMu.Unlock()
		return NewProtector(namespace, spy)
	}

	// setup Factory and overwrite default durations with short values
	idle := 500 * time.Millisecond
	period := 100 * time.Millisecond
	within := 5 * time.Second // generous: only a broken monitor reaches it
	f := NewFactory(builder, func(fc *factoryConfig) {
		fc.idleTimeout = idle
		fc.monitorPeriod = period
	})
	fi := f

	// init two Protectors & assert registry count
	_, _ = f.Instance("namespace_1")
	_, _ = f.Instance("namespace_1")
	_, _ = f.Instance("namespace_2")
	if got := protectorCount(fi); got != 2 {
		t.Fatalf("expect Protectors count be 2, got %d", got)
	}

	// start monitoring
	f.Monitor(ctx)

	// Monitor clears every Protector, then keeps clearing them periodically.
	for _, n := range []int{1, 2} {
		for _, ns := range []string{"namespace_1", "namespace_2"} {
			spy := spyOf(ns)
			eventually(t, within, func() bool { return spy.count() >= n },
				"expect Clear called at least %d times", n)
		}
	}

	// Inactive Protectors are removed from the registry once idle.
	eventually(t, within, func() bool { return protectorCount(fi) == 0 },
		"expect idle Protectors removed from the registry")

	// init a new Protector, then cancel the context.
	_, _ = f.Instance("namespace_2")
	if got := protectorCount(fi); got != 1 {
		t.Fatalf("expect Protectors count be 1, got %d", got)
	}
	p3spy := spyOf("namespace_2")
	eventually(t, within, func() bool { return p3spy.count() >= 1 },
		"expect the new *Protector cleared")

	cancelCtx()

	// The Protector is removed on shutdown even though it is not idle.
	eventually(t, within, func() bool { return protectorCount(fi) == 0 },
		"expect Protectors removed from the registry on shutdown")
}

// Regression: the clear func returned by Instance works after Monitor
// evicted the entry, and does not race with the registry.
func TestFactory_ClearFuncAfterEviction(t *testing.T) {
	ctx := context.Background()
	spy := newSpyCache()
	p := NewProtector("tenant-evicted", spy)
	f := NewFactory(func(namespace string) *Protector { return p })

	_, clear := f.Instance("tenant-evicted")
	f.clear(ctx, true) // what Monitor does on shutdown or for an idle entry

	clear() // used to panic: nil registry entry
	if got := spy.count(); got != 2 {
		t.Fatalf("expect Clear called twice, got %d", got)
	}

	// Concurrent Instance, eviction and clear funcs: clean under -race.
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(3)
		go func() { defer wg.Done(); _, c := f.Instance("tenant-evicted"); c() }()
		go func() { defer wg.Done(); f.clear(ctx, true) }()
		go func() { defer wg.Done(); clear() }()
	}
	wg.Wait()
}
