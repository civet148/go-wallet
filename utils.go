package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/civet148/log"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func DecodeHexString(s string) (b []byte, err error) {
	if b, err = hexutil.Decode(s); err != nil {
		if b, err = hex.DecodeString(s); err != nil {
			log.Errorf(err.Error())
			return nil, err
		}
	}
	return
}

func VerifySignatureKeccak256(strAddress, strMsg, strSignature string) bool {
	sig, err := DecodeHexString(strSignature)
	if err != nil {
		log.Errorf("decode hex error [%s]", err)
		return false
	}
	msg := accounts.TextHash([]byte(strMsg))
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1

	recovered, err := crypto.SigToPub(msg, sig)
	if err != nil {
		return false
	}
	recoveredAddr := crypto.PubkeyToAddress(*recovered)
	return strAddress == recoveredAddr.Hex()
}

func VerifySignatureSHA256(strAddress, strMsg, strSignature string) (bool, error) {

	strPubKey, err := RecoverPubKeySHA256(strMsg, strSignature)
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

func RecoverPubKeyKeccak256(strMsg, strSignature string) (string, error) {
	var publicKey []byte
	sig, err := DecodeHexString(strSignature)
	if err != nil {
		log.Errorf("decode hex error [%s]", err)
		return "", err
	}
	msg := accounts.TextHash([]byte(strMsg))
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1

	pubKeyECDSA, err := crypto.SigToPub(msg, sig)
	if err != nil {
		return "", err
	}
	publicKey = crypto.CompressPubkey(pubKeyECDSA)
	return hex.EncodeToString(publicKey), nil
}

func RecoverPubKeySHA256(strMsg, strSignature string) (string, error) {
	var publicKey []byte
	strHash := SignHash(strMsg)
	hash, err := DecodeHexString(strHash)
	if err != nil {
		log.Errorf("decode hex error [%s]", err)
		return "", err
	}
	signature, err := DecodeHexString(strSignature)
	if err != nil {
		log.Errorf("decode hex error [%s]", err)
		return "", err
	}
	pubKeyECDSA, err := crypto.SigToPub(hash, signature)
	if err != nil {
		log.Errorf("convert to ECDSA error [%s]", err)
		return "", err
	}
	publicKey = crypto.CompressPubkey(pubKeyECDSA)
	return hex.EncodeToString(publicKey), nil
}

func PublicKey2Address(strPublicKey string) (string, error) {
	publicKey, err := DecodeHexString(strPublicKey)
	if err != nil {
		log.Errorf("decode hex error [%s]", err)
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

