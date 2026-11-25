package privacytest

import (
	"cmp"
	"context"
	"crypto/rand"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/ln80/privacy-engine/core"
)

func keysEqual[T cmp.Ordered](x, y []T) bool {
	x, y = slices.Clone(x), slices.Clone(y)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func randomID() string {
	return fmt.Sprintf("%x", randomBytes(8))
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func newNamespace(prefix string) string {
	return prefix + "-" + randomID()
}

// randomKeyGen returns a fresh 32-byte key on every call, so concurrent
// creators of one ID each hold a different candidate.
func randomKeyGen(context.Context, string, string) ([]byte, error) {
	return randomBytes(32), nil
}

// margin is how long past a deadline the suites wait, to absorb clock skew
// and slow storage.
func margin(d time.Duration) time.Duration {
	return max(d/5, 50*time.Millisecond)
}

// keyIDs returns the IDs of keys, sorted.
func keyIDs(keys core.KeyMap) []string {
	return slices.Sorted(maps.Keys(keys))
}
