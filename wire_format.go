package privacy

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	ErrInvalidWireFormat = errors.New("invalid wire format")
)

const (
	wireFormatPrefix       = "ENC."
	wireFormatLegacyPrefix = "<pii:"
)

var (
	wireFormatRegex       = regexp.MustCompile(`^ENC\.\d*\.[A-Za-z0-9+/]+={0,2}\.[A-Za-z0-9+/]+={0,2}$`)
	wireFormatLegacyRegex = regexp.MustCompile(`^<pii:\d*:[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}$`)
)

func CheckFormat(str string) error {
	if valid := isWireFormatted(str); !valid {
		return ErrInvalidWireFormat
	}
	return nil
}

func isWireFormatted(str string) bool {
	if strings.HasPrefix(str, wireFormatPrefix) {
		return wireFormatRegex.MatchString(str)
	}
	if strings.HasPrefix(str, wireFormatLegacyPrefix) {
		return wireFormatLegacyRegex.MatchString(str)
	}
	return false
}

func wireFormat(subjectID string, cipherText []byte, version ...int) string {
	v := ""
	if len(version) > 0 && version[0] > 1 {
		v = strconv.Itoa(version[0])
	}

	base64SubjectID := base64.StdEncoding.EncodeToString([]byte(subjectID))
	base64CipherText := base64.StdEncoding.EncodeToString(cipherText)

	return wireFormatPrefix + v + "." + base64SubjectID + "." + base64CipherText
}

func parseWireFormat(str string) (version int, subjectID string, cipherText []byte, err error) {
	if err = CheckFormat(str); err != nil {
		return
	}

	var parts []string
	switch {
	case strings.HasPrefix(str, wireFormatPrefix):
		parts = strings.SplitN(strings.TrimPrefix(str, wireFormatPrefix), ".", 3)
	case strings.HasPrefix(str, wireFormatLegacyPrefix):
		parts = strings.SplitN(strings.TrimPrefix(str, wireFormatLegacyPrefix), ":", 3)
	}

	version = 1
	if len(parts[0]) > 0 {
		version, err = strconv.Atoi(parts[0])
		if err != nil {
			err = errors.Join(ErrInvalidWireFormat, err)
			return
		}
	}
	var subjectBytes []byte
	subjectBytes, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		err = errors.Join(ErrInvalidWireFormat, err)
		return
	}
	subjectID = string(subjectBytes)

	cipherText, err = base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		err = errors.Join(ErrInvalidWireFormat, err)
		return
	}

	return
}
