package create_keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// CreateKeyPair generates an Ed25519 public and private key pair.
// If seed is provided, it generates the key pair deterministically from the seed; otherwise, it generates a random key pair.
func CreateEd25519KeyPair(seed ...[]byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	if len(seed) > 0 && len(seed[0]) == ed25519.SeedSize {
		privateKey := ed25519.NewKeyFromSeed(seed[0])
		return privateKey.Public().(ed25519.PublicKey), privateKey
	}
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error CreateEd25519KeyPair: " + err.Error())
	}
	return pubKey, privKey
}
