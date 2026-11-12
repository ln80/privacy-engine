package privacy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestWireFormatRoundTrip(t *testing.T) {
	for _, v := range []wireValue{
		{subjectID: "u1", alg: 1, keyVersion: 1, ciphertext: []byte{0xde, 0xad}},
		{subjectID: "445d4aa3-5e05-4071-a070-09a13911d3a1", alg: 1, keyVersion: 1, ciphertext: bytes.Repeat([]byte{7}, 45)},
		{subjectID: "sub_ü/+=.?", alg: 0xff, keyVersion: 0xffffffff, ciphertext: []byte{0}},
		{subjectID: strings.Repeat("s", maxWireSubjectID), alg: 1, keyVersion: 1, ciphertext: []byte{1}},
	} {
		encoded := encodeWireValue(v)
		if !strings.HasPrefix(encoded, "ENC.") || strings.Count(encoded, ".") != 2 {
			t.Fatalf("unexpected shape %q", encoded)
		}
		if strings.ContainsAny(encoded, "+/=") {
			t.Fatalf("expect base64url without padding, got %q", encoded)
		}
		got, err := parseWireValue(encoded)
		if err != nil {
			t.Fatalf("%q: %v", encoded, err)
		}
		if got.subjectID != v.subjectID || got.alg != v.alg || got.keyVersion != v.keyVersion || !bytes.Equal(got.ciphertext, v.ciphertext) {
			t.Fatalf("round trip mismatch: %+v != %+v", got, v)
		}
	}
}

// A known value pins the byte layout: alg | keyVersion (BE) | ciphertext.
func TestWireFormatLayout(t *testing.T) {
	got := encodeWireValue(wireValue{subjectID: "u1", alg: 1, keyVersion: 1, ciphertext: []byte{0xaa, 0xbb}})
	if want := "ENC.dTE.AQAAAAGquw"; got != want {
		t.Fatalf("expect %q, got %q", want, got)
	}
}

func TestWireFormatRejects(t *testing.T) {
	url := base64.RawURLEncoding.EncodeToString
	payload := url([]byte{1, 0, 0, 0, 1, 0xaa})
	cases := map[string]string{
		"empty":                    "",
		"plaintext":                "alice@example.org",
		"prefix only":              "ENC.",
		"no payload":               "ENC." + url([]byte("u1")),
		"empty subject":            "ENC.." + payload,
		"empty payload":            "ENC." + url([]byte("u1")) + ".",
		"extra part":               "ENC." + url([]byte("u1")) + "." + payload + ".x",
		"v1 with version field":    "ENC..dTE=.AQID",
		"v1 explicit version":      "ENC.2.dTE=.AQID",
		"legacy pii form":          "<pii::dTE=:AQID",
		"lowercase prefix":         "enc." + url([]byte("u1")) + "." + payload,
		"std alphabet":             "ENC." + url([]byte("u1")) + ".+/+/",
		"padding":                  "ENC.dTE=." + payload,
		"non-canonical base64":     "ENC.dTF." + payload, // "dTF" decodes to "u1" with non-zero trailing bits
		"header only":              "ENC." + url([]byte("u1")) + "." + url([]byte{1, 0, 0, 0, 1}),
		"short header":             "ENC." + url([]byte("u1")) + "." + url([]byte{1, 0}),
		"subject too long":         "ENC." + url(bytes.Repeat([]byte("s"), maxWireSubjectID+1)) + "." + payload,
		"whitespace":               "ENC. " + url([]byte("u1")) + "." + payload,
		"trailing newline payload": "ENC." + url([]byte("u1")) + "." + payload + "\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseWireValue(in); !errors.Is(err, ErrInvalidWireFormat) {
				t.Fatalf("%q: expect ErrInvalidWireFormat, got %v", in, err)
			}
			if isWireFormatted(in) {
				t.Fatalf("%q: expect not wire formatted", in)
			}
		})
	}
}

// FuzzParseWireValue: parsing never panics, and every accepted value has
// exactly one textual form (it re-encodes to the same string).
func FuzzParseWireValue(f *testing.F) {
	f.Add("ENC.dTE.AQAAAAGquw")
	f.Add("ENC..dTE=.AQID")
	f.Add("<pii::dTE=:AQID")
	f.Add("ENC.dTE.AQAAAAE")
	f.Fuzz(func(t *testing.T, in string) {
		v, err := parseWireValue(in)
		if err != nil {
			return
		}
		if out := encodeWireValue(v); out != in {
			t.Fatalf("accepted %q but it re-encodes to %q", in, out)
		}
	})
}
