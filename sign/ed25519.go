package sign

import (
	//ed55519 "github.com/GoKillers/libsodium-go/cryptosign"
	"crypto/ed25519"
)

// // CryptoSign signs the message with the provided secret key
// func CryptoSign(message, secretKey []byte) ([]byte, int) {
// 	return ed55519.CryptoSign(message, secretKey)
// }

// SignMessage signs the provided message using the given private key.
func SignEd25519Message(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}
