package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/civet148/log"
	"github.com/ethereum/go-ethereum/crypto"
	"strings"
)

const (
	HEX_PREFIX = "0x"
)

func trimHexPrefix(strIn string) string {
	if hasTrimHexPrefix(strIn) {
		strIn = strings.TrimPrefix(strIn, HEX_PREFIX)
	}
	return strIn
}

func hasTrimHexPrefix(strIn string) bool {
	if strings.HasPrefix(strIn, HEX_PREFIX) {
		return true
	}
	return false
}

func VerifyMessage(strAddress, strMsg, strSignature string) (bool, error) {

	strSignature = trimHexPrefix(strSignature)
	strHash := SignHash(strMsg)
	strPubKey, err := RecoverPubKey(strHash, strSignature)
	if err != nil {
		log.Errorf(err.Error())
		return false, err
	}
	strAddr, err := PublicKey2Address(strPubKey)
	if err != nil {
		log.Errorf(err.Error())
		return false, err
	}
	if strAddr != strAddress {
		return false, fmt.Errorf("verify message failed")
	}
	return true, nil
}

func SignHash(text string) (strMsgHash string) {
	digestHash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(digestHash[:])
}

func RecoverPubKey(strMsgHash, strSignature string) (string, error) {
	strMsgHash = trimHexPrefix(strMsgHash)
	strSignature = trimHexPrefix(strSignature)
	hash, err := hex.DecodeString(strMsgHash)
	if err != nil {
		log.Errorf("msg hash hex decode error [%s]", err.Error())
		return "", err
	}
	signature, err := hex.DecodeString(strSignature)
	if err != nil {
		log.Errorf("signature hex decode error [%s]", err.Error())
		return "", err
	}
	var publicKey []byte
	pubKeyECDSA, err := crypto.SigToPub(hash, signature)
	if err != nil {
		log.Errorf("convert to ECDSA error [%s]", err)
		return "", err
	}
	publicKey = crypto.CompressPubkey(pubKeyECDSA)
	return hex.EncodeToString(publicKey), nil
}

func PublicKey2Address(strPublicKey string) (string, error) {
	strPublicKey = trimHexPrefix(strPublicKey)
	publicKey, err := hex.DecodeString(strPublicKey)
	if err != nil {
		log.Errorf("hex decode [%s] error [%s]", strPublicKey, err)
		return "", err
	}
	if len(publicKey) == compressedPubKeyLen {
		pk, err := crypto.DecompressPubkey(publicKey)
		if err != nil {
			log.Errorf("decompress public key error [%s]", err)
			panic("decompress public key failed")
		}
		publicKey = crypto.FromECDSAPub(pk)
	}
	pubKeyECDSA, err := crypto.UnmarshalPubkey(publicKey)
	if err != nil {
		log.Errorf("unmarshal pub key [%s] to ECDSA error [%s]", strPublicKey, err)
		return "", err
	}

	addr := crypto.PubkeyToAddress(*pubKeyECDSA)
	return addr.Hex(), nil
}
