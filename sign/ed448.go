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
