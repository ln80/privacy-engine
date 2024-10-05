package privacytest

import (
	"cmp"
	"crypto/rand"
	"fmt"
	"io"
	"reflect"
	"slices"
)

func keysEqual[T cmp.Ordered](x, y []T) bool {
	slices.Sort(x)
	slices.Sort(y)
	return reflect.DeepEqual(x, y)
}

func randomID() string {
	data := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}

	return fmt.Sprintf("%x", data)
}
