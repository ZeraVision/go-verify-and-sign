package verify

import (
	// // ed25519 "github.com/GoKillers/libsodium-go/cryptosign"
	"crypto/ed25519"
)

// // // CryptoVerify verifies the signature of the message with the provided public key
// // func CryptoVerify(message, signature, publicKey []byte) bool {
// // 	// If the verification is successful, it will return the message. Otherwise, it will return an error code.
// // 	_, errCode := ed25519.CryptoSignOpen(signature, publicKey)
// // 	return errCode >= 0
// // }

// VerifySignature verifies the signature for the given message using the provided public key.
func VerifyEd25519Signature(publicKey ed25519.PublicKey, message []byte, signature []byte) bool {

	return ed25519.Verify(publicKey, message, signature)
}
