package transcode

import (
	"fmt"
	"regexp"
)

func HashToHexString(byteHash []byte) string {

	re := regexp.MustCompile(`(.*)(s\d+)$`)

	// Unpack hash and check if there is a subhash
	hash := string(byteHash)
	_ = hash
	matches := re.FindSubmatch(byteHash)

	var hexHash string
	if len(matches) > 2 {
		hexHash = HexEncode(matches[1]) + string(matches[2])
	} else {
		hexHash = HexEncode(byteHash)
	}

	return hexHash
}

func HashToHexByte(stringHash string) ([]byte, error) {
	var transactionHashByte []byte
	var err error

	re := regexp.MustCompile(`(.*)(s\d+)$`)
	matches := re.FindStringSubmatch(stringHash)

	if len(matches) > 2 {
		result, err := HexDecode(matches[1])
		if err != nil {
			fmt.Println("Error HashToHexByte: more than 2 matches")
		}

		//transactionHashByte = []byte(result) + []byte(matches[2])

		transactionHashByte = append([]byte(result), []byte(matches[2])...)

	} else {

		transactionHashByte, err = HexDecode(stringHash)
		if err != nil {
			fmt.Println("Error HashToHexByte: failed to decode transactionHashByte")
		}
	}

	return transactionHashByte, err
}
