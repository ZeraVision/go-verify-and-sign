package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/ZeraVision/go-verify-and-sign/transcode"
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

func ImportEd25519KeyPair(publicKeyStr, privateKeyStr string) (ed25519.PublicKey, ed25519.PrivateKey, error) {

	_, pubKeyBytes, _, err := transcode.Base58DecodePublicKey(publicKeyStr)

	if err != nil {
		fmt.Println("ImportEd25519KeyPair: " + err.Error())
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("ImportEd25519KeyPair: Invalid length for public key")
	}

	privKeyBytes, err := transcode.Base58Decode(privateKeyStr)

	if err != nil {
		fmt.Println("ImportEd25519KeyPair: " + err.Error())
	}

	if len(privKeyBytes) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("ImportEd25519KeyPair: Invalid length for private key")
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)
	privKey := ed25519.PrivateKey(privKeyBytes)

	return pubKey, privKey, nil
}
