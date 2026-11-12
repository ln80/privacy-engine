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

func TestFactory(t *testing.T) {

	assertProtectorCount := func(t *testing.T, f *factory, count int) {
		f.mu.Lock()
		defer f.mu.Unlock()

		if want, got := count, len(f.reg); want != got {
			t.Fatalf("expect Protectors count be %d, got %d", want, got)
		}
	}

	assertCalls := func(t *testing.T, spy *spyProtector, min int) {
		spy.mu.Lock()
		defer spy.mu.Unlock()

		spy.Calls.AssertCount(t, "Clear", min)
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

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
	margin := 10 * time.Millisecond
	f := NewFactory(builder, func(fc *FactoryConfig) {
		fc.IDLE = idle
		fc.MonitorPeriod = period
	})

	// init two Protectors & assert registry count
	p1, _ := f.Instance("namespace_1")
	_, _ = f.Instance("namespace_1")
	p2, _ := f.Instance("namespace_2")

	assertProtectorCount(t, f.(*factory), 2)

	// start monitoring
	f.Monitor(ctx)

	// wait and spy Protectors' calls execs
	time.Sleep(margin)
	time.Sleep(period)

	assertCalls(t, p1.(*spyProtector), 1)
	assertCalls(t, p2.(*spyProtector), 1)

	// assert Monitor periodically clears resources
	time.Sleep(period)

	assertCalls(t, p1.(*spyProtector), 2)
	assertCalls(t, p2.(*spyProtector), 2)

	// assert sure Factory already deleted inactive Protectors from registry
	time.Sleep(idle)
	time.Sleep(margin)

	assertProtectorCount(t, f.(*factory), 0)

	// init a new Protector and force context cancellation
	p3, _ := f.Instance("namespace_2")

	if want, got := 1, len(f.(*factory).reg); want != got {
		t.Fatalf("expect %d, %d be equals", want, got)
	}

	time.Sleep(margin)
	time.Sleep(period)

	assertCalls(t, p3.(*spyProtector), 1)

	cancelCtx()

	time.Sleep(margin)

	// assert Protector was deleted from registry even is not IDLE
	assertProtectorCount(t, f.(*factory), 0)
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
