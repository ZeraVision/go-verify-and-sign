package create_keys

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"
)

// CreateKeyPair generates an Ed448 public and private key pair.
// If a seed is provided, it generates the key pair deterministically from the seed.
func CreateEd448KeyPair(seed ...[]byte) (ed448.PublicKey, ed448.PrivateKey) {
	if len(seed) > 0 {
		privateKey := ed448.NewKeyFromSeed(seed[0])
		publicKey := privateKey.Public().(ed448.PublicKey)
		return publicKey, privateKey
	}
	pubKey, privKey, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("CreateEd448KeyPair: " + err.Error())
	}
	return pubKey, privKey
}
