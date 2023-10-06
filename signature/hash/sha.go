package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"log"
)

// SHA256 calculates the SHA256 hash of a byte slice and returns the hash as a byte slice.
func SHA256(input []byte) []byte {
	hasher := sha256.New()
	_, err := hasher.Write(input)
	if err != nil {
		log.Fatal(err)
	}
	return hasher.Sum(nil)
}

// SHA512 calculates the SHA512 hash of a byte slice and returns the hash as a byte slice.
func SHA512(input []byte) []byte {
	hasher := sha512.New()
	_, err := hasher.Write(input)
	if err != nil {
		log.Fatal(err)
	}
	return hasher.Sum(nil)
}
