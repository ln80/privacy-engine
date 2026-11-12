package core

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
)

// Redaction of secrets and personal data (PE-09).
//
// Key, IDKey and TokenData must never print their value by accident: not in
// fmt with any verb (%v %+v %#v %s %q %x %d ...), not in log/slog, not in
// encoding/json or any encoder that uses encoding.TextMarshaler (including map
// keys, except string-kind map keys: see ValueTokenMap.MarshalJSON). Each
// prints a fixed placeholder instead. Marshaling redacts rather
// than fails, so a log line holding one of these values still renders.
//
// Getting the real value is always explicit: []byte(key), IDKey.Key(),
// TokenData.Reveal(). Persisting a value through JSON stores the placeholder,
// so never serialize these types to storage.
const (
	keyPlaceholder       = "KEY-*****"
	tokenDataPlaceholder = "**TOKEN DATA**" // #nosec G101 -- a redaction placeholder, not a credential
)

func formatPlaceholder(f fmt.State, verb rune, placeholder, goSyntax string) {
	switch {
	case verb == 'v' && f.Flag('#'):
		_, _ = f.Write([]byte(goSyntax))
	case verb == 'q':
		_, _ = f.Write([]byte(strconv.Quote(placeholder)))
	default:
		_, _ = f.Write([]byte(placeholder))
	}
}

// String implements fmt.Stringer.
func (k Key) String() string { return keyPlaceholder }

// GoString implements fmt.GoStringer.
func (k Key) GoString() string { return "core.Key(" + strconv.Quote(keyPlaceholder) + ")" }

// Format implements fmt.Formatter, so every verb prints the placeholder.
func (k Key) Format(f fmt.State, verb rune) {
	formatPlaceholder(f, verb, keyPlaceholder, k.GoString())
}

// LogValue implements slog.LogValuer.
func (k Key) LogValue() slog.Value { return slog.StringValue(keyPlaceholder) }

// MarshalText implements encoding.TextMarshaler.
func (k Key) MarshalText() ([]byte, error) { return []byte(keyPlaceholder), nil }

// MarshalJSON implements json.Marshaler.
func (k Key) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(keyPlaceholder)), nil }

// String implements fmt.Stringer. fmt never calls methods on unexported
// fields, so IDKey redacts as a whole rather than relying on Key's methods.
func (ik IDKey) String() string { return "{" + ik.id + " " + keyPlaceholder + "}" }

// GoString implements fmt.GoStringer.
func (ik IDKey) GoString() string {
	return "core.IDKey{id:" + strconv.Quote(ik.id) + ", key:" + strconv.Quote(keyPlaceholder) + "}"
}

// Format implements fmt.Formatter.
func (ik IDKey) Format(f fmt.State, verb rune) {
	formatPlaceholder(f, verb, ik.String(), ik.GoString())
}

// LogValue implements slog.LogValuer.
func (ik IDKey) LogValue() slog.Value {
	return slog.GroupValue(slog.String("id", ik.id), slog.String("key", keyPlaceholder))
}

// MarshalJSON implements json.Marshaler.
func (ik IDKey) MarshalJSON() ([]byte, error) {
	return []byte(`{"id":` + strconv.Quote(ik.id) + `,"key":` + strconv.Quote(keyPlaceholder) + `}`), nil
}

// String implements fmt.Stringer.
func (t TokenData) String() string { return tokenDataPlaceholder }

// GoString implements fmt.GoStringer.
func (t TokenData) GoString() string {
	return "core.TokenData(" + strconv.Quote(tokenDataPlaceholder) + ")"
}

// Format implements fmt.Formatter, so every verb prints the placeholder.
func (t TokenData) Format(f fmt.State, verb rune) {
	formatPlaceholder(f, verb, tokenDataPlaceholder, t.GoString())
}

// LogValue implements slog.LogValuer.
func (t TokenData) LogValue() slog.Value { return slog.StringValue(tokenDataPlaceholder) }

// MarshalText implements encoding.TextMarshaler (also used for map keys,
// as in ValueTokenMap).
func (t TokenData) MarshalText() ([]byte, error) { return []byte(tokenDataPlaceholder), nil }

// MarshalJSON implements json.Marshaler.
func (t TokenData) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(tokenDataPlaceholder)), nil
}

// MarshalJSON implements json.Marshaler. encoding/json uses a map key's
// string value directly when the key type is a string kind, without calling
// MarshalText, so the default encoding of this map would put every token
// value in clear in its keys. It is encoded instead as the list of its
// records, sorted by token, each with a redacted value.
//
// A map keyed by TokenData declared elsewhere has the same problem: never
// JSON-encode one.
func (m ValueTokenMap) MarshalJSON() ([]byte, error) {
	records := make([]TokenRecord, 0, len(m))
	for _, r := range m {
		records = append(records, r)
	}
	slices.SortFunc(records, func(a, b TokenRecord) int { return strings.Compare(a.Token, b.Token) })
	return json.Marshal(records)
}
