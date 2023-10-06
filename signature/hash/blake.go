package hash

import (
	"log"

	"github.com/zeebo/blake3"
)

// Blake3 calculates the BLAKE3 hash of a byte slice and returns the hash as a byte slice.
func Blake3(input []byte) []byte {
	hasher := blake3.New()
	_, err := hasher.Write(input)
	if err != nil {
		log.Fatal(err)
	}
	return hasher.Sum(nil)
}
