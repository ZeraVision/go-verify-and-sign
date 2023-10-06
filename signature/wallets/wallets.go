package wallets

import (
	"fmt"
	"signature/transcode"
)

//

func PublicKeyToWallet(encoded []byte) string {
	var identifier, publicKey []byte

	if len(encoded) < 5 {
		fmt.Println("PublicKeyToWallet: encoded invalid")
		return ""
	}

	// Split data
	identifier = encoded[:2]
	publicKey = encoded[2:]

	identifierStr := string(identifier)

	if identifierStr == "a_" {
		return transcode.Base58Encode(A_Hashing(publicKey))
	} else if identifierStr == "b_" {
		return transcode.Base58Encode(B_Hashing(publicKey))
	} else if identifierStr == "c_" {
		return transcode.Base58Encode(C_Hashing(publicKey))
	} else if identifierStr == "r_" {
		return transcode.Base58Encode(R_Hashing(publicKey))
	}

	return "invalid_wallet_address"
}
