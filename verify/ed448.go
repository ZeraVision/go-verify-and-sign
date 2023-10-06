package verify

import (
	////"github.com/ZeraVision/go-verify-and-sign/hash"
	"github.com/cloudflare/circl/sign/ed448"
)

// VerifySignature verifies the signature of the given message using the provided public key and context.
func VerifyEd448Signature(publicKey ed448.PublicKey, message []byte, signature []byte, ctx string) bool {
	return ed448.Verify(publicKey, message, signature, ctx)
}

// // // VerifyEd448Signature verifies the signature of the digested message using the provided public key and context.
// // func VerifyEd448Signature(publicKey ed448.PublicKey, message []byte, signature []byte, ctx string) bool {
// // 	// First, digest the message using SHA-512
// // 	hashedMessage := hash.SHA512(message)

// // 	// Verify the signature against the hashed message
// // 	return ed448.Verify(publicKey, hashedMessage[:], signature, ctx)
// // }

// // // VerifyEd448Signature verifies the signature of the digested message using the provided public key and context.
// // func VerifyEd448Signature(publicKey ed448.PublicKey, message []byte, signature []byte, ctx string) bool {
// // 	// First, digest the message using SHAKE256
// // 	hashedMessage := make([]byte, 64) // 512 bits = 64 bytes
// // 	sha3.ShakeSum256(hashedMessage, message)

// // 	// Verify the signature against the hashed message
// // 	return ed448.Verify(publicKey, hashedMessage, signature, ctx)
// // }

// // func VerifyEd448Signature(publicKey ed448.PublicKey, message, signature []byte) bool {
// // 	return ed448.Verify(publicKey, message, signature, "")
// // }
