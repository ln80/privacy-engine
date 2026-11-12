package core

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// PE-09 regression: keys and token data never print their value.

var (
	secretKey  = Key(bytes.Repeat([]byte{0xAB}, 32))
	secretData = TokenData("alice@example.org")
)

// leaks reports whether out contains the secret in any common encoding.
func leaks(out string) bool {
	k := []byte(secretKey)
	for _, form := range []string{
		hex.EncodeToString(k[:4]),
		strings.ToUpper(hex.EncodeToString(k[:4])),
		base64.StdEncoding.EncodeToString(k[:6]),
		base64.RawURLEncoding.EncodeToString(k[:6]),
		"171 171", "0xab, 0xab", "\\xab\\xab",
		"alice", "example.org",
	} {
		if strings.Contains(out, form) {
			return true
		}
	}
	return false
}

func TestRedactFmt(t *testing.T) {
	values := map[string]any{
		"Key":         secretKey,
		"*Key":        &secretKey,
		"IDKey":       NewIDKey("u1", secretKey),
		"KeyMap":      KeyMap{"u1": secretKey},
		"TokenData":   secretData,
		"TokenRecord": TokenRecord{Token: "t1", Value: secretData},
		"ValueTokenMap": ValueTokenMap{
			secretData: {Token: "t1", Value: secretData},
		},
		"TokenValueMap": TokenValueMap{"t1": {Token: "t1", Value: secretData}},
	}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T %v", "%10v", "%-10s"}
	for name, v := range values {
		for _, verb := range verbs {
			if out := fmt.Sprintf(verb, v); leaks(out) {
				t.Errorf("%s with %s leaks: %s", name, verb, out)
			}
		}
		for _, out := range []string{fmt.Sprint(v), fmt.Sprintln(v)} {
			if leaks(out) {
				t.Errorf("%s with Sprint leaks: %s", name, out)
			}
		}
	}
}

func TestRedactJSON(t *testing.T) {
	values := map[string]any{
		"Key":           secretKey,
		"IDKey":         NewIDKey("u1", secretKey),
		"KeyMap":        KeyMap{"u1": secretKey},
		"TokenData":     secretData,
		"TokenRecord":   TokenRecord{Token: "t1", Value: secretData},
		"ValueTokenMap": ValueTokenMap{secretData: {Token: "t1", Value: secretData}},
		"nested": struct {
			K Key
			R []TokenRecord
		}{secretKey, []TokenRecord{{Token: "t1", Value: secretData}}},
	}
	for name, v := range values {
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if leaks(string(out)) {
			t.Errorf("%s JSON leaks: %s", name, out)
		}
		if !json.Valid(out) {
			t.Errorf("%s: invalid JSON %s", name, out)
		}
	}
}

func TestRedactSlog(t *testing.T) {
	for name, newHandler := range map[string]func(*bytes.Buffer) slog.Handler{
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
	} {
		var buf bytes.Buffer
		slog.New(newHandler(&buf)).Info("event",
			"key", secretKey,
			"idkey", NewIDKey("u1", secretKey),
			"keys", KeyMap{"u1": secretKey},
			"data", secretData,
			"record", TokenRecord{Token: "t1", Value: secretData},
			slog.Any("any", secretData),
			slog.Group("g", "key", secretKey, "data", secretData),
		)
		if leaks(buf.String()) {
			t.Errorf("slog %s handler leaks: %s", name, buf.String())
		}
	}
}

// Redaction must not get in the way of explicit access.
func TestRedactKeepsExplicitAccess(t *testing.T) {
	if secretData.Reveal() != "alice@example.org" {
		t.Fatal("Reveal must return the value")
	}
	if !bytes.Equal([]byte(secretKey), bytes.Repeat([]byte{0xAB}, 32)) {
		t.Fatal("[]byte(key) must return the bytes")
	}
	if !bytes.Equal(NewIDKey("u1", secretKey).Key(), secretKey) {
		t.Fatal("IDKey.Key must return the key")
	}
	if got := fmt.Sprintf("%q", secretData); got != `"**TOKEN DATA**"` {
		t.Fatalf("%%q: got %s", got)
	}
}

func TestValueTokenMapJSONIsAListOfRecords(t *testing.T) {
	m := ValueTokenMap{
		"bob@example.org": {Token: "t2", Value: "bob@example.org"},
		secretData:        {Token: "t1", Value: secretData},
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"Token":"t1","Value":"**TOKEN DATA**"},{"Token":"t2","Value":"**TOKEN DATA**"}]`
	if string(out) != want {
		t.Fatalf("expect %s, got %s", want, out)
	}
}
