package transcode

import (
	"encoding/hex"
	"fmt"
)

func HexEncode(input []byte) string {
	return hex.EncodeToString(input)
}

func HexDecode(encoded string) ([]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	return decoded, nil
}
