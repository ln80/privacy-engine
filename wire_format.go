package privacy

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

var (
	ErrInvalidWireFormat = errors.New("invalid wire format")
)

// Field wire format v2 (docs/wire-format-v2.md):
//
//	value   = "ENC." base64url(subjectID) "." base64url(payload)      (no padding)
//	payload = alg (1) | keyVersion (4, BE) | ciphertext
//
// ciphertext is whatever the Encryptor produced for alg (for AES-256-GCM:
// nonce | ciphertext | tag). alg and keyVersion are authenticated by the
// Encryptor through core.Binding, so editing them fails decryption. Only this
// format is parsed: there is no version field in the text and no legacy form.
const (
	wireFormatPrefix = "ENC."
	wireSeparator    = "."

	wireHeaderSize   = 1 + 4
	maxWireSubjectID = 1024
)

// wireEncoding is base64url without padding. Strict decoding rejects
// non-canonical trailing bits; isWireAlphabet rejects the \r and \n the
// decoder would otherwise skip. Together they give each value exactly one
// textual form.
var wireEncoding = base64.RawURLEncoding.Strict()

func isWireAlphabet(s string) bool {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// wireValue is a parsed field value.
type wireValue struct {
	subjectID  string
	alg        uint8
	keyVersion uint32
	ciphertext []byte
}

// CheckFormat returns ErrInvalidWireFormat if str is not a field value in
// wire format v2. It checks the structure only, not that the value decrypts.
func CheckFormat(str string) error {
	_, err := parseWireValue(str)
	return err
}

func isWireFormatted(str string) bool {
	return CheckFormat(str) == nil
}

func encodeWireValue(v wireValue) string {
	payload := make([]byte, 0, wireHeaderSize+len(v.ciphertext))
	payload = append(payload, v.alg)
	payload = binary.BigEndian.AppendUint32(payload, v.keyVersion)
	payload = append(payload, v.ciphertext...)

	return wireFormatPrefix +
		wireEncoding.EncodeToString([]byte(v.subjectID)) +
		wireSeparator +
		wireEncoding.EncodeToString(payload)
}

// parseWireValue parses a field value. Any deviation from the format,
// including legacy forms, is ErrInvalidWireFormat; it never panics.
func parseWireValue(str string) (v wireValue, err error) {
	rest, ok := strings.CutPrefix(str, wireFormatPrefix)
	if !ok {
		return v, ErrInvalidWireFormat
	}
	encSubject, encPayload, ok := strings.Cut(rest, wireSeparator)
	if !ok || encSubject == "" || encPayload == "" || !isWireAlphabet(encSubject) || !isWireAlphabet(encPayload) {
		return v, ErrInvalidWireFormat
	}
	if wireEncoding.EncodedLen(maxWireSubjectID) < len(encSubject) {
		return v, errors.Join(ErrInvalidWireFormat, errors.New("subject id too long"))
	}

	subject, err := wireEncoding.DecodeString(encSubject)
	if err != nil {
		return v, errors.Join(ErrInvalidWireFormat, err)
	}
	if len(subject) == 0 || len(subject) > maxWireSubjectID {
		return v, errors.Join(ErrInvalidWireFormat, errors.New("subject id length out of range"))
	}

	payload, err := wireEncoding.DecodeString(encPayload)
	if err != nil {
		return v, errors.Join(ErrInvalidWireFormat, err)
	}
	// The header must be followed by a ciphertext; the Encryptor checks its own
	// minimum length (nonce + tag for AES-256-GCM, PE-03).
	if len(payload) <= wireHeaderSize {
		return v, errors.Join(ErrInvalidWireFormat, errors.New("payload too short"))
	}

	return wireValue{
		subjectID:  string(subject),
		alg:        payload[0],
		keyVersion: binary.BigEndian.Uint32(payload[1:wireHeaderSize]),
		ciphertext: payload[wireHeaderSize:],
	}, nil
}
