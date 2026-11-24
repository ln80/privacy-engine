package core

import (
	"encoding/xml"
	"slices"
	"testing"
)

// R-CS-9: String and MarshalText redact too, for code that calls them directly
// or encoders that use them (encoding/xml, map keys, text loggers).
func TestRedactStringAndText(t *testing.T) {
	for name, v := range map[string]interface {
		String() string
		MarshalText() ([]byte, error)
	}{
		"Key":       secretKey,
		"TokenData": secretData,
	} {
		text, err := v.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		if leaks(v.String()) || leaks(string(text)) {
			t.Fatalf("%s leaks through String or MarshalText", name)
		}
	}
	out, err := xml.Marshal(xmlHolder{K: secretKey})
	if err != nil || leaks(string(out)) {
		t.Fatalf("encoding/xml leaks a key: %s, %v", out, err)
	}
	if ik := NewIDKey("u1", secretKey); ik.ID() != "u1" || leaks(ik.String()) {
		t.Fatal("IDKey: expect its ID and a redacted String")
	}
}

type xmlHolder struct{ K Key }

func TestTokenHelpers(t *testing.T) {
	m := TokenValueMap{
		"t1": {Token: "t1", Value: "a"},
		"t2": {Token: "t2", Value: "b"},
	}
	vals := m.Values()
	slices.Sort(vals)
	if !slices.Equal(vals, []TokenData{"a", "b"}) {
		t.Fatalf("Values: got %v", vals)
	}
	if (&IndexTakenError{Token: "t1"}).Error() == "" {
		t.Fatal("IndexTakenError: empty message")
	}
}
