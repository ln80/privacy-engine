package privacy

import (
	"context"
	"testing"
	"time"

	"github.com/ln80/privacy-engine/aes"
	"github.com/ln80/privacy-engine/core"
	"github.com/ln80/privacy-engine/memory"
)

func configOf(p *Protector) *ProtectorConfig { return p.cfg }

func TestProtectorOptions(t *testing.T) {
	tokens := memory.NewTokenEngine()
	enc := aes.New256GCMEncryptor()
	auditor := AuditorFunc(func(context.Context, AuditEvent) error { return nil })

	c := configOf(NewProtector("ns", memory.NewKeyEngine(),
		WithTokenEngine(tokens),
		WithEncryptor(enc),
		WithCacheTTL(time.Minute),
		WithImmediateErasure(),
		WithMultipleSubjects(),
		WithForgottenValue("[erased]"),
		WithAuditor(auditor),
	))
	if c.TokenEngine != tokens || c.Encryptor != enc || c.Auditor == nil {
		t.Fatal("expect token engine, encryptor and auditor set")
	}
	if !c.CacheEnabled || c.CacheTTL != time.Minute {
		t.Fatalf("expect cache on for 1m, got %v %v", c.CacheEnabled, c.CacheTTL)
	}
	if c.GracefulMode || !c.MultipleSubjects || c.ForgottenValue != "[erased]" {
		t.Fatalf("unexpected config %+v", c)
	}

	if c := configOf(NewProtector("ns", memory.NewKeyEngine())); !c.GracefulMode || !c.CacheEnabled {
		t.Fatal("expect graceful mode and cache on by default")
	}
	if c := configOf(NewProtector("ns", memory.NewKeyEngine(), WithCacheTTL(-time.Second))); c.CacheTTL != 0 {
		t.Fatalf("expect a negative TTL to keep the default, got %v", c.CacheTTL)
	}
	if c := configOf(NewProtector("ns", memory.NewKeyEngine(), WithoutCache())); c.CacheEnabled {
		t.Fatal("expect cache off")
	}
}

// Closures over the config remain valid options, alone or mixed with With*.
func TestProtectorClosuresStillWork(t *testing.T) {
	c := configOf(NewProtector("ns", memory.NewKeyEngine(),
		WithForgottenValue("x"),
		func(pc *ProtectorConfig) { pc.GracefulMode = false },
	))
	if c.GracefulMode || c.ForgottenValue != "x" {
		t.Fatalf("unexpected config %+v", c)
	}
}

func TestFactoryOptions(t *testing.T) {
	f := NewFactory(func(ns string) *Protector { return NewProtector(ns, memory.NewKeyEngine()) },
		WithIdleTimeout(time.Hour), WithMonitorPeriod(time.Minute))
	if f.IDLE != time.Hour || f.MonitorPeriod != time.Minute {
		t.Fatalf("unexpected config %+v", f.FactoryConfig)
	}
}

func TestMemoryWithGracePeriod(t *testing.T) {
	if got := core.GracePeriodOf(memory.NewKeyEngine(memory.WithGracePeriod(time.Hour))); got != time.Hour {
		t.Fatalf("expect 1h, got %v", got)
	}
}
