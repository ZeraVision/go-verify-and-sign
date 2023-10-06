package sign

import (
	"fmt"

	"github.com/ZeraVision/go-verify-and-sign/verify"
	"github.com/cloudflare/circl/sign/ed448"
)

// SignMessage signs the given message using the provided private key and context.
func SignEd448Message(privateKey ed448.PrivateKey, message []byte, ctx string) ([]byte, bool) {
	signature := ed448.Sign(privateKey, message, ctx)

	if !verify.VerifyEd448Signature(privateKey.Public().(ed448.PublicKey), message, signature, ctx) {
		fmt.Println("SignEd448Message: Failed to self verify")
		return signature, false
	}

	return signature, true
}

// // // SignEd448Message signs the digested message using the provided private key and context.
// // func SignEd448Message(privateKey ed448.PrivateKey, message []byte, ctx string) ([]byte, bool) {
// // 	// First, digest the message using SHA-512
// // 	hashedMessage := hash.SHA512(message)

// // 	// Sign the hashed message
// // 	signature := ed448.Sign(privateKey, hashedMessage[:], ctx)

// // 	// Using your verify function to check if the signature is valid (you'll need to modify this function too, as per the previous example)
// // 	if !verify.VerifyEd448Signature(privateKey.Public().(ed448.PublicKey), message, signature, ctx) {
// // 		fmt.Println("SignEd448Message: Failed to self verify")
// // 		return signature, false
// // 	}

// // 	return signature, true
// // }

// // // Sign a message using the private key
// // func SignEd448Message(privateKey ed448.PrivateKey, message []byte) []byte {
// // 	signature, _ := privateKey.Sign(message, nil, nil)
// // 	return signature[:]
// // }

// // // SignEd448Message signs the digested message using the provided private key and context.
// // func SignEd448Message(privateKey ed448.PrivateKey, message []byte, ctx string) ([]byte, bool) {
// // 	// First, digest the message using SHAKE256. Assuming you want a 512-bit output.
// // 	hashedMessage := make([]byte, 64) // 512 bits = 64 bytes
// // 	sha3.ShakeSum256(hashedMessage, message)

// // 	// Sign the hashed message
// // 	signature := ed448.Sign(privateKey, hashedMessage, ctx)

// // 	// Using your verify function to check if the signature is valid
// // 	if !verify.VerifyEd448Signature(privateKey.Public().(ed448.PublicKey), message, signature, ctx) {
// // 		fmt.Println("SignEd448Message: Failed to self verify")
// // 		return signature, false
// // 	}

// // 	return signature, true
// // }

// // func SignEd448Message(privateKey ed448.PrivateKey, message []byte) ([]byte, error) {
// // 	// Sign the message with the provided private key
// // 	signature := ed448.Sign(privateKey, message, "")

// // 	// Use the public key derived from the private key to verify the signature
// // 	publicKey := privateKey.Public().(ed448.PublicKey)

// // 	if !ed448.Verify(publicKey, message, signature, "") {
// // 		return nil, fmt.Errorf("SignEd448Message: Failed to self-verify the signature")
// // 	}

// // 	return signature, nil
// // }
