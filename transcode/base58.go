package transcode

import (
	"fmt"
	"math/big"
	"strings"
)

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// ! should this be in this file?
func Base58EncodePublicKey(publicKey []byte) string {
	return string(publicKey[:2]) + Base58Encode(publicKey[2:])
}

func Base58Encode(input interface{}) string {
	var data []byte
	switch v := input.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	default:
		return ""
	}

	x := big.NewInt(0).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	encoded := ""

	for x.Cmp(zero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, base, mod)
		encoded = string(base58Alphabet[mod.Int64()]) + encoded
	}

	for _, b := range data {
		if b != 0x00 {
			break
		}
		encoded = string(base58Alphabet[0]) + encoded
	}

	return encoded
}

func Base58Decode(encoded string) ([]byte, error) {
	decoded := big.NewInt(0)
	base := big.NewInt(58)
	alphabet := make(map[byte]int64)
	for i, char := range base58Alphabet {
		alphabet[byte(char)] = int64(i)
	}

	for i := 0; i < len(encoded); i++ {
		value, ok := alphabet[encoded[i]]
		if !ok {
			return nil, fmt.Errorf("invalid character in input")
		}

		decoded.Mul(decoded, base)
		decoded.Add(decoded, big.NewInt(value))
	}

	decodedBytes := decoded.Bytes()

	for i := 0; i < len(encoded); i++ {
		if encoded[i] == base58Alphabet[0] {
			decodedBytes = append([]byte{0x00}, decodedBytes...)
		} else {
			break
		}
	}

	return decodedBytes, nil
}

// ! this function probably won't work with multisig keys in current state
func Base58DecodePublicKey(publicKey string) (prefix []byte, public []byte, combined []byte, err error) {
	// Find the last occurrence of '_'
	lastUnderscoreIndex := strings.LastIndex(publicKey, "_")

	// If no underscore is found, just decode everything
	if lastUnderscoreIndex == -1 {
		result, err := Base58Decode(publicKey)

		if err != nil {
			fmt.Println("Base58DecodePublicKey: " + err.Error())
		}

		return nil, result, result, err
	}

	// Extract the prefix and the part to decode
	prefixStr := publicKey[:lastUnderscoreIndex+1]
	toDecode := publicKey[lastUnderscoreIndex+1:]

	// Decode the part after the underscore
	decoded, err := Base58Decode(toDecode)
	if err != nil {
		return nil, nil, nil, err
	}

	// Prepend the prefix to the decoded byte array
	decodedWithPrefix := append([]byte(prefixStr), decoded...)

	return []byte(prefixStr), decoded, decodedWithPrefix, err
}
