/*
Package privacy provides tools for handling personal data (PII) in line with privacy-by-design principles:

  - Tokenization: Generates a random pseudonym for the given PII data.

  - Client-side encryption: Performed at the struct field level.

  - Crypto-shredding: By discarding the encryption key, access to the encrypted data is lost,
    which is particularly useful in cases involving immutable storage.

# Subject IDs

Subject IDs must be pseudonymous identifiers: random IDs or tokens from the
tokenizer. Never use an email, a name, or any other direct identifier as a
subject ID. Every encrypted field value names its subject in clear, as the
record's own subjectID field does, so a direct identifier would sit in clear
next to every value and stay there after Forget. To key data on an email,
tokenize the email and use the token.

# Wire format

Encrypted field values look like:

	ENC.<base64url(subjectID)>.<base64url(alg | keyVersion | nonce | ciphertext | tag)>

The full specification of field values and streams, and the behaviour of
Encrypt and Decrypt for each key state, is in docs/wire-format-v2.md.
*/
package privacy
