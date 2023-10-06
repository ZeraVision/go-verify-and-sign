package sign

import (
	//ed55519 "github.com/GoKillers/libsodium-go/cryptosign"
	"crypto/ed25519"
	"fmt"

	"github.com/ZeraVision/go-verify-and-sign/verify"
)

// // CryptoSign signs the message with the provided secret key
// func CryptoSign(message, secretKey []byte) ([]byte, int) {
// 	return ed55519.CryptoSign(message, secretKey)
// }

// SignMessage signs the provided message using the given private key.
func SignEd25519Message(privateKey ed25519.PrivateKey, message []byte) ([]byte, bool) {
	signature := ed25519.Sign(privateKey, message)

	if !verify.VerifyEd25519Signature(privateKey.Public().(ed25519.PublicKey), message, signature) {
		fmt.Println("SignEd25519Message: Failed to self verify")
		return signature, false
	}

	return signature, true
}
