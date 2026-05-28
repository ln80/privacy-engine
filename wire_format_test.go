package privacy

import (
	"encoding/base64"
	"strconv"
	"testing"
)

func TestWireFormat(t *testing.T) {
	b64 := func(str string) string {
		return base64.StdEncoding.EncodeToString([]byte(str))
	}

	t.Run("new format detection", func(t *testing.T) {
		tcs := []struct {
			input           string
			isWireFormatted bool
		}{
			{"", false},
			{"ENC..", false},
			{"ENC.." + b64("abc") + "." + "UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=", true},
			{"ENC." + "4" + "." + b64("abc") + "." + "UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=", true},
		}

		for i, tc := range tcs {
			t.Run("tc: "+strconv.Itoa(i), func(t *testing.T) {
				if want, got := tc.isWireFormatted, isWireFormatted(tc.input); want != got {
					t.Fatalf("expect isWireFormatted=%v for %q", want, tc.input)
				}
			})
		}
	})

	t.Run("legacy format backward compat", func(t *testing.T) {
		tcs := []struct {
			input           string
			isWireFormatted bool
		}{
			{"<pii::", false},
			{"<PII::UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=", false},
			{"<pii::" + b64("abc") + ":" + "UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=", true},
			{"<pii:" + "4" + ":" + b64("abc") + ":" + "UM30Kh37phctoSNql2DUhpOOvIGdLKAqyoV45VQ=", true},
		}

		for i, tc := range tcs {
			t.Run("tc: "+strconv.Itoa(i), func(t *testing.T) {
				if want, got := tc.isWireFormatted, isWireFormatted(tc.input); want != got {
					t.Fatalf("expect isWireFormatted=%v for %q", want, tc.input)
				}
				if tc.isWireFormatted {
					version, subjectID, cipher, err := parseWireFormat(tc.input)
					if err != nil {
						t.Fatal("expect err be nil, got", err)
					}
					if version < 1 {
						t.Fatal("expect version >= 1, got", version)
					}
					if subjectID == "" {
						t.Fatal("expect subjectID not empty")
					}
					if len(cipher) == 0 {
						t.Fatal("expect cipher not empty")
					}
				}
			})
		}
	})

	t.Run("round trip", func(t *testing.T) {
		subjectID := "user-123"
		cipher := []byte("encrypted-data-bytes")

		encoded := wireFormat(subjectID, cipher)
		if !isWireFormatted(encoded) {
			t.Fatalf("expect output to be wire formatted: %s", encoded)
		}

		version, gotSubject, gotCipher, err := parseWireFormat(encoded)
		if err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if version != 1 {
			t.Fatalf("expect version 1, got %d", version)
		}
		if gotSubject != subjectID {
			t.Fatalf("expect subjectID %q, got %q", subjectID, gotSubject)
		}
		if string(gotCipher) != string(cipher) {
			t.Fatal("expect cipher to match")
		}

		encoded2 := wireFormat(subjectID, cipher, 2)
		version2, _, _, err := parseWireFormat(encoded2)
		if err != nil {
			t.Fatal("expect err be nil, got", err)
		}
		if version2 != 2 {
			t.Fatalf("expect version 2, got %d", version2)
		}
	})
}
