package wallet

import (
	"encoding/hex"
	"github.com/civet148/log"
	"github.com/ethereum/go-ethereum/crypto"
)

func RecoverPubKey(strMsgHash, strSignature string) (string, error) {
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
