package utils

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/lightningnetwork/lnd/lntypes"
	"gopkg.in/macaroon.v2"
)

func ParseLsatHeader(authField string) (*macaroon.Macaroon, lntypes.Preimage, error) {
	// A typical authField
	// Authorization: L402 AGIAJEemVQUTEyNCR0exk7ek90Cg==:1234abcd1234abcd1234abcd
	if len(authField) == 0 {
		return nil, lntypes.Preimage{}, fmt.Errorf("Authorization Field not present")
	}
	// Trim leading and trailing spaces
	authField = strings.TrimSpace(authField)
	if len(authField) == 0 {
		return nil, lntypes.Preimage{}, fmt.Errorf("L402 Header is not present")
	}
	// Trim L402 prefix
	token := strings.TrimPrefix(authField, "L402 ")
	splitted := strings.Split(token, ":")
	if len(splitted) != 2 {
		return nil, lntypes.Preimage{}, fmt.Errorf("L402 does not have the right format: %s", authField)
	}
	macaroonString := strings.TrimSpace(splitted[0])
	preimageString := strings.TrimSpace(splitted[1])

	mac, err := GetMacaroonFromString(macaroonString)
	if err != nil {
		return nil, lntypes.Preimage{}, err
	}

	preimage, err := GetPreimageFromString(preimageString)
	if err != nil {
		return mac, lntypes.Preimage{}, err
	}
	return mac, preimage, nil
}

func ParseLnAddress(address string) (string, string, error) {
	address = strings.TrimSpace(address)
	addressSplit := strings.Split(address, "@")
	if len(addressSplit) != 2 {
		return "", "", fmt.Errorf("Invalid lightning address")
	}
	username := addressSplit[0]
	domain := addressSplit[1]
	return username, domain, nil
}

func GetMacaroonFromString(macaroonString string) (*macaroon.Macaroon, error) {
	if len(macaroonString) == 0 || !IsBase64(macaroonString) {
		return nil, fmt.Errorf("Invalid macaroon string")
	}
	macBytes, err := base64.StdEncoding.DecodeString(macaroonString)
	if err != nil {
		return nil, err
	}
	mac := &macaroon.Macaroon{}
	if err := mac.UnmarshalBinary(macBytes); err != nil {
		return nil, err
	}
	return mac, nil
}

func GetPreimageFromString(preimageString string) (lntypes.Preimage, error) {
	if len(preimageString) == 0 || !IsHex(preimageString) {
		return lntypes.Preimage{}, fmt.Errorf("Invalid preimage string")
	}
	preimage, err := lntypes.MakePreimageFromStr(preimageString)
	if err != nil {
		return lntypes.Preimage{}, err
	}
	return preimage, nil
}

func IsBase64(str string) bool {
	_, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return false
	}
	return true
}

func IsHex(str string) bool {
	_, err := hex.DecodeString(str)
	if err != nil {
		return false
	}
	return true
}

func GetRootKey() []byte {
	rootKey := []byte(os.Getenv("ROOT_KEY"))
	return rootKey
}
