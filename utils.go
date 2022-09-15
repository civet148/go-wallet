package wallet

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/civet148/log"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gagliardetto/solana-go"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/sha3"
	"strings"
)

const (
	//Number of bytes in a pubkey.
	PublicKeyLength = 32
	//Maximum length of derived pubkey seed.
	MaxSeedLength = 32
	//Maximum number of seeds.
	MaxSeeds = 16
	//Number of bytes in a signature.
	SignatureLength = 64
	//Maximum string length of a base58 encoded pubkey.
	MaxBase58Length = 44
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


//VerifySignatureSolana for Solana phantom signature verification
//strAddress base58 encoded public key
//strSignature base58 encoded signature
//strMsg base64 encoded message
func VerifySignatureSolana(strAddress, strMsg, strSignature string) (bool, error) {
	sig := solana.MustSignatureFromBase58(strSignature)
	addr := solana.MustPublicKeyFromBase58(strAddress)
	msg, err := base64.StdEncoding.DecodeString(strMsg)
	if err != nil {
		log.Errorf(err.Error())
		return false, err
	}
	return sig.Verify(addr, msg), nil
}


//VerifyKeccak256 for metamask eth_sign signature verification
func VerifyKeccak256(strAddress, strMsg, strSignature string) (bool, error) {
	sig, err := DecodeHexString(strSignature)
	if err != nil {
		log.Errorf("decode hex error [%s]", err)
		return false, err
	}
	msg := accounts.TextHash([]byte(strMsg))
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1

	recovered, err := crypto.SigToPub(msg, sig)
	if err != nil {
		log.Errorf("SigToPub error [%s]", err.Error())
		return false, err
	}
	recoveredAddr := crypto.PubkeyToAddress(*recovered)
	return strings.EqualFold(strAddress, recoveredAddr.Hex()), nil
}

//VerifyLegacyKeccak256 for BCOS signature verification
func VerifyLegacyKeccak256(strAddress, strMsg, strSignature string) (bool, error) {

	strPubKey, err := RecoverLegacyKeccak256Msg(strMsg, strSignature)
	if err != nil {
		log.Errorf(err.Error())
		return false, err
	}
	strAddr, err := PublicKey2Address(strPubKey)
	if err != nil {
		log.Errorf(err.Error())
		return false, err
	}
	return strings.EqualFold(strAddr, strAddress), nil
}

func LegacyKeccak256Hash(data []byte) string {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(data)
	return hex.EncodeToString(hasher.Sum(nil))
}

func PersonalSignHash(data []byte) string {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), string(data))
	return LegacyKeccak256Hash([]byte(msg))
}

//RecoverKeccak256Msg for metamask eth_sign signature
func RecoverKeccak256Msg(strMsg, strSignature string) (string, error) {
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


func RecoverKeccak256Hash(strHash, strSignature string) (string, error) {
	var publicKey []byte
	sig, err := DecodeHexString(strSignature)
	if err != nil {
		log.Errorf("decode hex error [%s]", err)
		return "", err
	}
	msg , err := DecodeHexString(strHash)
	if err != nil {
		log.Errorf("decode hex error [%s]", err)
		return "", err
	}
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1

	pubKeyECDSA, err := crypto.SigToPub(msg, sig)
	if err != nil {
		return "", err
	}
	publicKey = crypto.CompressPubkey(pubKeyECDSA)
	return hex.EncodeToString(publicKey), nil
}

func RecoverLegacyKeccak256Msg(strMsg, strSignature string) (string, error) {
	var publicKey []byte
	strHash := LegacyKeccak256Hash([]byte(strMsg))
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


func RecoverLegacyKeccak256Hash(strHash, strSignature string) (strPubKey string, err error) {
	var publicKey []byte
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


func signatureFromBase58(in string) (out solana.Signature, err error) {
	val, err := base58.Decode(in)
	if err != nil {
		return
	}

	if len(val) != SignatureLength {
		err = fmt.Errorf("invalid length, expected 64, got %d", len(val))
		return
	}
	copy(out[:], val)
	return
}

func MustSignatureFromBase58(in string) solana.Signature {
	out, err := signatureFromBase58(in)
	if err != nil {
		panic(err)
	}
	return out
}