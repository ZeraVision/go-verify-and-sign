package wallets

import "github.com/ZeraVision/go-verify-and-sign/hash"

func A_Hashing(publicKey []byte) []byte {
	return hash.Blake3(publicKey)
}

func B_Hashing(publicKey []byte) []byte {
	return hash.Blake3(hash.SHA256(publicKey))
}

func C_Hashing(publicKey []byte) []byte {
	return hash.Blake3(hash.SHA512(publicKey))
}

func R_Hashing(publicKey []byte) []byte {
	return hash.Blake3(hash.SHA512(publicKey))
}
