/*
Package privacy provides tools for handling personal data (PII) in line with privacy-by-design principles:

  - Tokenization: Generates a random pseudonym for the given PII data.

  - Client-side encryption: Performed at the struct field level.

  - Crypto-shredding: By discarding the encryption key, access to the encrypted data is lost,
    which is particularly useful in cases involving immutable storage.
*/
package privacy
