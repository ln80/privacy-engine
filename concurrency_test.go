package privacy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

// Races at the Protector level, run with -race. Several Protectors on one
// engine stand for several instances of a service.

const racers = 16

type note struct {
	ID   string `pii:"subjectID"`
	Text string `pii:"data,replace=forgotten"`
}

// R-KE-3 seen from the application: instances that use a new subject at
// the same moment all encrypt under the one key that was stored.
func TestConcurrent_FirstUseAcrossInstances(t *testing.T) {
	ctx := t.Context()
	keys := memory.NewKeyEngine()
	notes := make([]note, racers)
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := range racers {
		wg.Go(func() {
			p := NewProtector("ns", keys) // an instance with its own cache
			notes[i] = note{ID: "sub_new", Text: fmt.Sprintf("note %d", i)}
			errs[i] = p.Encrypt(ctx, &notes[i])
		})
	}
	wg.Wait()

	reader := NewProtector("ns", keys, WithoutCache())
	for i := range racers {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if err := reader.Decrypt(ctx, &notes[i]); err != nil || notes[i].Text != fmt.Sprintf("note %d", i) {
			t.Fatalf("note %d does not decrypt under the stored key: %q, %v", i, notes[i].Text, err)
		}
	}
}

// Encrypt racing Forget: every value that was written is shredded with the
// subject, and every refused write says the subject is forgotten.
func TestConcurrent_EncryptRacingForget(t *testing.T) {
	ctx := t.Context()
	keys := memory.NewKeyEngine()
	p := NewProtector("ns", keys)
	seed := note{ID: "sub_1", Text: "first"}
	if err := p.Encrypt(ctx, &seed); err != nil {
		t.Fatal(err)
	}

	var (
		mu      sync.Mutex
		written []note
		wg      sync.WaitGroup
	)
	start := make(chan struct{})
	for i := range racers {
		wg.Go(func() {
			<-start
			for j := range 20 {
				n := note{ID: "sub_1", Text: fmt.Sprintf("note %d-%d", i, j)}
				err := p.Encrypt(ctx, &n)
				switch {
				case err == nil:
					mu.Lock()
					written = append(written, n)
					mu.Unlock()
				case !errors.Is(err, ErrSubjectForgotten):
					t.Errorf("Encrypt: expect success or ErrSubjectForgotten, got %v", err)
					return
				}
			}
		})
	}
	wg.Go(func() {
		<-start
		if err := p.Forget(ctx, "sub_1"); err != nil {
			t.Errorf("Forget: %v", err)
		}
	})
	close(start)
	wg.Wait()

	reader := NewProtector("ns", keys, WithoutCache())
	for _, n := range append(written, seed) {
		if err := reader.Decrypt(ctx, &n); err != nil || n.Text != "forgotten" {
			t.Fatalf("a value written during Forget is not shredded: %q, %v", n.Text, err)
		}
	}
	if err := p.Encrypt(ctx, &note{ID: "sub_1", Text: "late"}); !errors.Is(err, ErrSubjectForgotten) {
		t.Fatalf("Encrypt after Forget: expect ErrSubjectForgotten, got %v", err)
	}
}

// Forget and Recover flipping while other goroutines read: a read gives the
// plaintext or the placeholder, never an error or another value.
func TestConcurrent_ForgetRecoverWhileReading(t *testing.T) {
	ctx := t.Context()
	keys := memory.NewKeyEngine(memory.WithGracePeriod(time.Hour))
	p := NewProtector("ns", keys, WithCacheTTL(time.Millisecond))
	stored := note{ID: "sub_1", Text: "secret"}
	if err := p.Encrypt(ctx, &stored); err != nil {
		t.Fatal(err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	for range racers {
		wg.Go(func() {
			for !stop.Load() {
				n := stored
				if err := p.Decrypt(ctx, &n); err != nil {
					t.Errorf("Decrypt: %v", err)
					return
				}
				if n.Text != "secret" && n.Text != "forgotten" {
					t.Errorf("Decrypt returned %q", n.Text)
					return
				}
			}
		})
	}
	for range 50 {
		if err := p.Forget(ctx, "sub_1"); err != nil {
			t.Fatal(err)
		}
		if err := p.Recover(ctx, "sub_1"); err != nil {
			t.Fatal(err)
		}
	}
	stop.Store(true)
	wg.Wait()

	n := stored
	if err := p.Decrypt(ctx, &n); err != nil || n.Text != "secret" {
		t.Fatalf("after the last Recover: expect the plaintext, got %q, %v", n.Text, err)
	}
}

// R-TK-2 seen from the application: instances tokenizing one value at once
// get one token.
func TestConcurrent_TokenizeAcrossInstances(t *testing.T) {
	ctx := t.Context()
	keys, tokens := memory.NewKeyEngine(), memory.NewTokenEngine()
	got := make([]string, racers)
	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			p := NewProtector("ns", keys, WithTokenEngine(tokens))
			res, err := p.Tokenize(ctx, TokenDataSlice("alice@example.com"))
			if err != nil {
				t.Errorf("Tokenize: %v", err)
				return
			}
			got[i] = res.Get("alice@example.com").Token
		})
	}
	wg.Wait()
	for i := range got {
		if got[i] == "" || got[i] != got[0] {
			t.Fatalf("expect one token for one value, got %v", got)
		}
	}
}

// The factory evicting idle Protectors and clearing caches while requests
// use them: no request fails or reads another tenant's data.
func TestConcurrent_FactoryEvictsWhileInUse(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	keys := memory.NewKeyEngine()
	f := NewFactory(func(ns string) *Protector { return NewProtector(ns, keys, WithCacheTTL(time.Millisecond)) },
		WithIdleTimeout(time.Millisecond), WithMonitorPeriod(time.Millisecond))
	f.Monitor(ctx)

	var wg sync.WaitGroup
	for i := range racers {
		wg.Go(func() {
			ns := fmt.Sprintf("tenant-%d", i%3)
			for j := range 50 {
				p, done := f.Instance(ns)
				n := note{ID: "sub_1", Text: fmt.Sprintf("%s %d", ns, j)}
				want := n.Text
				err := p.Encrypt(ctx, &n)
				if err == nil {
					err = p.Decrypt(ctx, &n)
				}
				done()
				if err != nil || n.Text != want {
					t.Errorf("%s: round trip gave %q, %v", ns, n.Text, err)
					return
				}
			}
		})
	}
	wg.Wait()

	// Each tenant has its own key: tenant-0's value does not open in tenant-1.
	p0, done0 := f.Instance("tenant-0")
	defer done0()
	n := note{ID: "sub_1", Text: "x"}
	if err := p0.Encrypt(ctx, &n); err != nil {
		t.Fatal(err)
	}
	p1, done1 := f.Instance("tenant-1")
	defer done1()
	if err := p1.Decrypt(ctx, &n); !errors.Is(err, core.ErrDecryptionFailure) {
		t.Fatalf("expect another tenant's value refused, got %v", err)
	}
}
