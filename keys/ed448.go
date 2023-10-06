package keys

import (
	"crypto/rand"
	"fmt"

	"github.com/ZeraVision/go-verify-and-sign/transcode"

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

func ImportEd448KeyPair(publicKeyStr, privateKeyStr string) (ed448.PublicKey, ed448.PrivateKey, error) {
	_, pubKeyBytes, _, err := transcode.Base58DecodePublicKey(publicKeyStr)

	if err != nil {
		fmt.Println("ImportEd448KeyPair: " + err.Error())
	}

	if len(pubKeyBytes) != ed448.PublicKeySize {
		return nil, nil, fmt.Errorf("Invalid length for public key")
	}

	privKeyBytes, err := transcode.Base58Decode(privateKeyStr)

	if err != nil {
		fmt.Println("ImportEd448KeyPair: " + err.Error())
	}

	privKeyBytes = append(privKeyBytes, pubKeyBytes...)

	if len(privKeyBytes) != ed448.PrivateKeySize {
		return nil, nil, fmt.Errorf("Invalid length for private key")
	}

	pubKey := ed448.PublicKey(pubKeyBytes)
	privKey := ed448.PrivateKey(privKeyBytes)

	return pubKey, privKey, nil
}
