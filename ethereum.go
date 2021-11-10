package wallet

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"github.com/civet148/log"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miguelmota/go-ethereum-hdwallet"
	"github.com/tyler-smith/go-bip39"
)

const (
	compressedPubKeyLen = 33
)

var (
	DerivationPath0 = "m/44'/60'/0'/0/0"
	DerivationPath1 = "m/44'/60'/0'/0/1"
)

type WalletEthereum struct {
	Address    string
	PrivateKey string
	PublicKey  string
	Phrase     string
	Seed       string
}

type walletAccount struct {
	strPhrase string
	strSeed   string
	wallet    *hdwallet.Wallet
	account   accounts.Account
}

func NewWalletEthereum(op OpType, args ...string) Wallet {
	w := &WalletEthereum{}
	switch op {
	case OpType_Load:
		{
			w.Address = args[0]
			w.PrivateKey = args[1]
			w.PublicKey = args[2]
			w.Phrase = args[3]
		}
	case OpType_Create:
		return w.Create()
	case OpType_Recover:
		return w.Recover(args[0])
	case OpType_Verify:
		{
			w.PublicKey = args[0]
		}
	}
	return w
}

func (m *WalletEthereum) Create() Wallet {

	entropy, err := bip39.NewEntropy(DefaultBitSize)
	if err != nil {
		log.Errorf("new entropy error [%s]", err)
		panic(err.Error())
	}
	wa := m.createWalletAccount(DerivationPath0, entropy, "")
	m.Address = wa.AddressHex()
	m.PrivateKey = wa.PrivateKeyHex()
	m.PublicKey = wa.PublicKeyHex()
	m.Phrase = wa.Phrase()
	return m
}

func (m *WalletEthereum) Recover(strPhrase string) Wallet {
	entropy, err := bip39.EntropyFromMnemonic(strPhrase)
	if err != nil {
		log.Errorf("new entropy from phrase error [%s]", err.Error())
		panic(err.Error())
	}
	wa := m.createWalletAccount(DerivationPath0, entropy, strPhrase)
	m.Address = wa.AddressHex()
	m.PrivateKey = wa.PrivateKeyHex()
	m.PublicKey = wa.PublicKeyHex()
	m.Phrase = wa.Phrase()
	return m
}

func (m *WalletEthereum) sign(privateKey []byte, digestHash []byte) (signature []byte, err error) {
	var pk *ecdsa.PrivateKey
	if pk, err = crypto.ToECDSA(privateKey); err != nil {
		log.Errorf("private key bytes to ECDSA PrivateKey error [%s]", err)
		panic(err.Error())
	}
	return crypto.Sign(digestHash, pk)
}

func (m *WalletEthereum) SignHash(digestHash []byte) (strSignature string, err error) {
	strPrivateKey := m.GetPrivateKey()
	if strPrivateKey == "" {
		panic("private key is nil")
	}
	var privateKey, sign []byte
	privateKey, err = hex.DecodeString(strPrivateKey)
	if err != nil {
		log.Errorf("hex decode [%s] error [%s]", strPrivateKey, err)
		return
	}
	if sign, err = m.sign(privateKey, digestHash); err != nil {
		log.Errorf("sign error [%s]", err)
		return
	}
	return hex.EncodeToString(sign), nil
}

func (m *WalletEthereum) SignText(text []byte) (strSignature string, err error) {
	digestHash := sha256.Sum256(text)
	return m.SignHash(digestHash[:])
}

func (m *WalletEthereum) verify(pubKey []byte, digestHash []byte, signature []byte) bool {
	return crypto.VerifySignature(pubKey, digestHash, signature[:len(signature)-1])
}

func (m *WalletEthereum) VerifyHash(digestHash []byte, strSignature string) bool {
	strPublicKey := m.GetPublicKey()
	if strPublicKey == "" {
		panic("public key is nil")
	}
	publicKey, err := hex.DecodeString(strPublicKey)
	if err != nil {
		log.Errorf("hex decode [%s] error [%s]", strPublicKey, err)
		return false
	}
	if len(publicKey) == compressedPubKeyLen {
		pk, err := crypto.DecompressPubkey(publicKey)
		if err != nil {
			log.Errorf("decompress public key error [%s]", err)
			panic("decompress public key failed")
		}
		publicKey = crypto.FromECDSAPub(pk)
	}
	sign, err := hex.DecodeString(strSignature)
	if err != nil {
		log.Errorf("hex decode [%s] error [%s]", strSignature, err)
		return false
	}
	return m.verify(publicKey, digestHash, sign)
}

func (m *WalletEthereum) VerifyText(text []byte, strSignature string) bool {
	digestHash := sha256.Sum256(text)
	return m.VerifyHash(digestHash[:], strSignature)
}

func (m *WalletEthereum) GetPrivateKey() string {
	return m.PrivateKey
}

func (m *WalletEthereum) GetPublicKey() string {
	return m.PublicKey
}

func (m *WalletEthereum) GetAddress() string {
	return m.Address
}

func (m *WalletEthereum) GetPhrase() string {
	return m.Phrase
}

func (m *WalletEthereum) createWalletAccount(derivationPath string, entropy []byte, strPhrase string) *walletAccount {
	var err error
	if len(entropy) == 0 {
		if entropy, err = bip39.NewEntropy(DefaultBitSize); err != nil {
			log.Errorf("new entropy error [%s]", err.Error())
			panic(err.Error())
		}
	}
	if strPhrase == "" {
		if strPhrase, err = bip39.NewMnemonic(entropy); err != nil {
			log.Errorf("new phrase error [%s]", err)
			panic(err.Error())
		}
	}

	seed := bip39.NewSeed(strPhrase, "")
	wallet, err := hdwallet.NewFromSeed(seed)
	if err != nil {
		log.Errorf("create wallet error [%s]", err)
		panic(err.Error())
	}
	path := hdwallet.MustParseDerivationPath(derivationPath)
	account, err := wallet.Derive(path, false)
	if err != nil {
		log.Errorf("wallet derive path [%s] error [%s]", path, err.Error())
		panic(err.Error())
	}
	strSeed := hex.EncodeToString(seed)

	return &walletAccount{
		wallet:    wallet,
		account:   account,
		strPhrase: strPhrase,
		strSeed:   strSeed,
	}
}

func (wa *walletAccount) AddressHex() string {
	return wa.account.Address.Hex()
}

func (wa *walletAccount) PrivateKeyHex() string {
	pk, _ := wa.wallet.PrivateKey(wa.account)
	return hex.EncodeToString(crypto.FromECDSA(pk))
}

func (wa *walletAccount) PublicKeyHex() string {
	pk, _ := wa.wallet.PublicKey(wa.account)
	pub := crypto.CompressPubkey(pk)
	return hex.EncodeToString(pub)
}

func (wa *walletAccount) Phrase() string {
	return wa.strPhrase
}
