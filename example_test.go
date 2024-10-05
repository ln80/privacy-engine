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
		return privacy.NewProtector(namespace, memory.NewKeyEngine(), func(pc *privacy.ProtectorConfig) {
			// Token engine is optional.
			// if not provided, the protector service will panic when trying to Tokenize/Detokenize sensitive data
			pc.TokenEngine = memory.NewTokenEngine()

			// If cache is enabled then the service will decorates engines
			// using an in-memory cache layer.
			pc.CacheEnabled = true
			pc.CacheTTL = 15 * time.Minute

			// AES is 256GCM is the default encryptor.
			pc.Encryptor = aes.New256GCMEncryptor()

			// This Allow a soft crypto-shredding of personal data,
			// so the data can be recovered within the grace period.
			pc.GracefulMode = true
		})
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
	tokens, err := protector.Tokenize(ctx, tenant, privacy.TokenDataSlice(p.Email))
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

	// Encrypted Output ex:
	// Profile{
	//  Email: "<pii::NDQ1ZDRhYTMtNWUwNS00MDcxLWEwNzAtMDlhMTM5MTFkM2Ex:7Q61HTCUT+XZtzzGp3HsVoHk6o74kwdEHqY46kB4eflXnRwswgHRVlApRg7mp4bNH5zSppV2u40=",
	//  Fullname: "<pii::NDQ1ZDRhYTMtNWUwNS00MDcxLWEwNzAtMDlhMTM5MTFkM2Ex:mNyZmcvUHTAKTMC+uY6f77bJ3sZ5+NYBZwWKj8zZ0sA4j8mOPz8188sV",
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
