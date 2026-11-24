// Package privacytest holds the conformance suites that every backend must
// pass, and test doubles.
//
//	TestEncryptor    core.Encryptor    requirements R-EN
//	TestKeyEngine    core.KeyEngine    requirements R-KE
//	TestKeyWrapper   core.KeyWrapper   requirements R-KW
//	TestTokenEngine  core.TokenEngine  requirements R-TE
//
// Each suite runs one subtest per requirement of docs/implementing-backends.md,
// named after its ID, so a failure names the rule it breaks:
//
//	func TestKeyStore(t *testing.T) {
//		privacytest.TestKeyEngine(t, mystore.NewKeyEngine(client), func(c *privacytest.KeyEngineTestConfig) {
//			c.GracePeriod = 2 * time.Second
//		})
//	}
//
// Run them against real storage or an emulator, not a mock.
package privacytest
