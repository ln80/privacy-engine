package privacy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/memory"
)

type spyProtector struct {
	Protector

	mu    sync.RWMutex
	Calls FuncCalls
}

func (tp *spyProtector) Clear(ctx context.Context, force bool) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if tp.Calls == nil {
		tp.Calls = NewFuncCalls()
	}
	tp.Calls["Clear"] = append(tp.Calls["Clear"], time.Now())

	return tp.Protector.Clear(ctx, force)
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
	protectorCount := func(f *factory) int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.reg)
	}
	clearCalls := func(spy *spyProtector) int {
		spy.mu.Lock()
		defer spy.mu.Unlock()
		return len(spy.Calls["Clear"])
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	builder := func(namespace string) Protector {
		return &spyProtector{
			Protector: NewProtector(namespace, memory.NewKeyEngine(), func(pc *ProtectorConfig) {
				pc.CacheEnabled = true
				pc.CacheTTL = 1
				pc.GracefulMode = true
			}),
		}
	}

	// setup Factory and overwrite default durations with short values
	idle := 500 * time.Millisecond
	period := 100 * time.Millisecond
	within := 5 * time.Second // generous: only a broken monitor reaches it
	f := NewFactory(builder, func(fc *FactoryConfig) {
		fc.IDLE = idle
		fc.MonitorPeriod = period
	})
	fi := f.(*factory)

	// init two Protectors & assert registry count
	p1, _ := f.Instance("namespace_1")
	_, _ = f.Instance("namespace_1")
	p2, _ := f.Instance("namespace_2")
	if got := protectorCount(fi); got != 2 {
		t.Fatalf("expect Protectors count be 2, got %d", got)
	}

	// start monitoring
	f.Monitor(ctx)

	// Monitor clears every Protector, then keeps clearing them periodically.
	for _, n := range []int{1, 2} {
		for _, p := range []Protector{p1, p2} {
			eventually(t, within, func() bool { return clearCalls(p.(*spyProtector)) >= n },
				"expect Clear called at least %d times", n)
		}
	}

	// Inactive Protectors are removed from the registry once idle.
	eventually(t, within, func() bool { return protectorCount(fi) == 0 },
		"expect idle Protectors removed from the registry")

	// init a new Protector, then cancel the context.
	p3, _ := f.Instance("namespace_2")
	if got := protectorCount(fi); got != 1 {
		t.Fatalf("expect Protectors count be 1, got %d", got)
	}
	eventually(t, within, func() bool { return clearCalls(p3.(*spyProtector)) >= 1 },
		"expect the new Protector cleared")

	cancelCtx()

	// The Protector is removed on shutdown even though it is not idle.
	eventually(t, within, func() bool { return protectorCount(fi) == 0 },
		"expect Protectors removed from the registry on shutdown")
}

// PE-07 regression: the clear func returned by Instance works after Monitor
// evicted the entry, and does not race with the registry.
func TestFactory_ClearFuncAfterEviction(t *testing.T) {
	ctx := context.Background()
	spy := &spyProtector{Protector: NewProtector("tenant-pe07", memory.NewKeyEngine()), Calls: NewFuncCalls()}
	f := NewFactory(func(namespace string) Protector { return spy }).(*factory)

	_, clear := f.Instance("tenant-pe07")
	f.clear(ctx, true) // what Monitor does on shutdown or for an idle entry

	clear() // used to panic: nil registry entry
	spy.Calls.AssertCount(t, "Clear", 2)

	// Concurrent Instance, eviction and clear funcs: clean under -race.
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(3)
		go func() { defer wg.Done(); _, c := f.Instance("tenant-pe07"); c() }()
		go func() { defer wg.Done(); f.clear(ctx, true) }()
		go func() { defer wg.Done(); clear() }()
	}
	wg.Wait()
}
