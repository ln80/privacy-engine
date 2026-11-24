package aes_test

import (
	"testing"

	"github.com/ln80/privacy-engine/aes"
	"github.com/ln80/privacy-engine/privacytest"
)

func TestEncryptorConformance(t *testing.T) {
	privacytest.TestEncryptor(t, aes.New256GCMEncryptor())
}
