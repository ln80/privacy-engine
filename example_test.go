package privacy_test

import (
	"context"
	"log"
	"time"

	"github.com/ln80/privacy-engine"
	"github.com/ln80/privacy-engine/aes"
	"github.com/ln80/privacy-engine/memory"
)

type Profile struct {
	Email    string `pii:"data"`
	Fullname string `pii:"data"`
	Role     string
}

type User struct {
	ID      string `pii:"subjectID"`
	Profile `pii:"dive"`
}

// Example of Tokenization and Client-side encryption
func Example() {
	ctx := context.Background()

	newProtector := func(namespace string) privacy.Protector {
		return privacy.NewProtector(namespace, memory.NewKeyEngine(),
			// The token engine is optional. Without it, the token methods
			// fail with core.ErrTokenEngineNotConfigured.
			privacy.WithTokenEngine(memory.NewTokenEngine()),

			// Keys are cached in memory; the TTL bounds how long a subject
			// forgotten by another instance stays readable here.
			privacy.WithCacheTTL(15*time.Minute),

			// AES-256-GCM is the default encryptor.
			privacy.WithEncryptor(aes.New256GCMEncryptor()),

			// Forget is graceful by default: keys are disabled and
			// recoverable for the grace period. WithImmediateErasure()
			// would erase at once.
		)
	}

	factory := privacy.NewFactory(newProtector)

	// Spin up a goroutine to particularly monitor and evict caches
	factory.Monitor(ctx)

	// tenant ID is used as namespace to ensure some degree of isolation.
	tenant := "tnt-a20873"

	protector, clear := factory.Instance(tenant)

	// Force the cache cleanup at the end of the function call.
	// Always be cautious about the cached encryption materials.
	defer clear()

	// A user profile data sent from the client-site
	p := Profile{
		Email:    "Samanta_Murray25@hotmail.com",
		Fullname: "Samanta Murray",
		Role:     "Teacher",
	}

	// Assuming the example function is a system entrypoint, an important step is
	// to tokenize the user canonical identifier (i.e., the email address)
	// as soon as possible in the process and use the token as a surrogate ID
	tokens, err := protector.Tokenize(ctx, privacy.TokenDataSlice(p.Email), privacy.WithPrefix("sub_"))
	if err != nil {
		log.Fatal(err)
	}

	id := tokens.Get(p.Email).Token

	// Note that the token (aka the surrogate ID) is used as PII subjectID,
	// Which means all user PII data will be encrypted using the same encryption key
	// that is uniquely associated to this token.
	user := User{ID: id, Profile: p}

	err = protector.Encrypt(ctx, &user)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypted Output ex. Each value is "ENC." base64url(subject ID) "."
	// base64url(algorithm | key version | nonce | ciphertext | tag):
	// Profile{
	//  Email: "ENC.c3ViXzQ0NWQ0YWEzLTVlMDUtNDA3MS1hMDcwLTA5YTEzOTExZDNhMQ.AQAAAAF6WKvFL27d6qSmx4qG0-OQcOpt-aT44gq_og-epYZtgKrp2FrtrmnmozA50uUDgz6bXT05mx1x1g",
	//  Fullname: "ENC.c3ViXzQ0NWQ0YWEzLTVlMDUtNDA3MS1hMDcwLTA5YTEzOTExZDNhMQ.AQAAAAFmmmUlER1itz4sjKMfNvpwwaD3NA6iSXmqQnEzxqnvNT4TIw_N9Et0Ozs",
	// 	Role: "Teacher",
	// }

	err = protector.Decrypt(ctx, &user)
	if err != nil {
		log.Fatal(err)
	}

	print(user.Profile)

	// If the encryption key is lost, PII can't be decrypted,
	// and data is removed from the structure.
	_ = protector.Encrypt(ctx, &user)
	_ = protector.Forget(ctx, user.ID)
	_ = protector.Decrypt(ctx, &user)

	print(user.Profile)

	// Output:
	// Profile{
	//   Email: "Samanta_Murray25@hotmail.com",
	//   Fullname: "Samanta Murray",
	//   Role: "Teacher",
	// }
	// Profile{
	//   Email: "",
	//   Fullname: "",
	//   Role: "Teacher",
	// }
}
