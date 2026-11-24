package privacytest

import (
	"bytes"
	"context"
	"testing"

	"github.com/ln80/privacy-engine/core"
)

// KeyWrapperTestConfig configures TestKeyWrapper.
type KeyWrapperTestConfig struct {
	// Namespace prefixes the namespaces the suite uses. Default "privacytest".
	Namespace string
}

// TestKeyWrapper is the conformance suite of core.KeyWrapper. It runs one
// subtest per checkable requirement of docs/implementing-backends.md (R-KW-5
// and R-KW-6 are not: the first is a rule for your releases, the second is
// envelope.KeyEngine's job). Run it against your real KMS or HSM, or its
// emulator.
//
// Then run TestKeyEngine on envelope.NewKeyEngine(wrapper, store) as well.
func TestKeyWrapper(t *testing.T, w core.KeyWrapper, opts ...func(*KeyWrapperTestConfig)) {
	t.Helper()
	cfg := &KeyWrapperTestConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "privacytest"
	}
	run := func(name string, f func(c *wrapCheck)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			f(&wrapCheck{t: t, ctx: t.Context(), w: w, ns: newNamespace(cfg.Namespace), prefix: cfg.Namespace})
		})
	}

	run("R-KW-1 a wrapped key unwraps only for its namespace and key ID", func(c *wrapCheck) {
		a, b := randomID(), randomID()
		plain, wrapped := c.generate(c.ns, a)
		got, err := c.w.UnwrapKey(c.ctx, c.ns, a, wrapped)
		if err != nil || !bytes.Equal(got, plain) {
			c.t.Fatalf("UnwrapKey with the same namespace and key ID: expect the data key, got error %v", err)
		}
		c.refused(newNamespace(c.prefix), a, wrapped, "another namespace")
		c.refused(c.ns, b, wrapped, "another key ID")
	})

	run("R-KW-2 the wrapped form does not reveal the data key", func(c *wrapCheck) {
		plain, wrapped := c.generate(c.ns, randomID())
		if len(wrapped) == 0 || bytes.Contains(wrapped, plain) {
			c.t.Fatal("the wrapped form is empty or contains the data key")
		}
	})

	run("R-KW-3 data keys are 32 random bytes", func(c *wrapCheck) {
		id := randomID()
		k1, _ := c.generate(c.ns, id)
		k2, _ := c.generate(c.ns, id)
		if len(k1) != 32 || len(k2) != 32 {
			c.t.Fatalf("expect 32-byte data keys, got %d and %d bytes", len(k1), len(k2))
		}
		if bytes.Equal(k1, make([]byte, 32)) || bytes.Equal(k1, k2) {
			c.t.Fatal("data keys are zero or repeat")
		}
	})

	run("R-KW-4 a tampered, truncated or foreign blob fails", func(c *wrapCheck) {
		a := randomID()
		_, wrapped := c.generate(c.ns, a)
		_, foreign := c.generate(c.ns, randomID())
		n := len(wrapped)
		flip := func(i int) []byte {
			b := bytes.Clone(wrapped)
			b[i] ^= 0x01
			return b
		}
		for name, blob := range map[string][]byte{
			"first byte flipped":  flip(0),
			"middle byte flipped": flip(n / 2),
			"last byte flipped":   flip(n - 1),
			"last byte cut":       wrapped[:n-1],
			"half cut":            wrapped[:n/2],
			"empty":               {},
			"random":              randomBytes(n),
			"extra byte":          append(bytes.Clone(wrapped), 0),
			"another key's blob":  foreign,
		} {
			c.refused(c.ns, a, blob, name)
		}
	})
}

type wrapCheck struct {
	t      *testing.T
	ctx    context.Context
	w      core.KeyWrapper
	ns     string
	prefix string
}

func (c *wrapCheck) generate(ns, keyID string) (core.Key, []byte) {
	c.t.Helper()
	plain, wrapped, err := c.w.GenerateKey(c.ctx, ns, keyID)
	if err != nil {
		c.t.Fatalf("GenerateKey: %v", err)
	}
	return plain, wrapped
}

func (c *wrapCheck) refused(ns, keyID string, blob []byte, what string) {
	c.t.Helper()
	got, err := c.w.UnwrapKey(c.ctx, ns, keyID, blob)
	if err == nil {
		c.t.Fatalf("UnwrapKey with %s: expect an error, got a key", what)
	}
	if len(got) != 0 {
		c.t.Fatalf("UnwrapKey with %s: returned bytes with its error", what)
	}
}
