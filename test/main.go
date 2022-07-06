package main

import (
	"github.com/civet148/go-wallet"
	"github.com/civet148/log"
)

type Person struct {
	Name     string `json:"name"`
	Age      int    `json:"age"`
	City     string `json:"city"`
	District string `json:"district"`
	Address  string `json:"address"`
}

func main() {
	VerifySignatureKeccak256()
	VerifySignatureLegacyKeccak256()
	WalletSignAndVerify()
}

func VerifySignatureLegacyKeccak256() {
	strHash := "924a14c42641d860962d8f19f6e4e147631b3f4b8745b57b07552db07a78f04f"
	strSig := "0df090d0600ad3387c0a8aa61ba9bf5127f88dc6fa2cb8e6d41b354f1f1cd9dd0ea40c7fccec2edcfd7c4296897a34a048084377b7cb6aa1f7b7b15015b5c2d100" //data app
	strPubKey, err := wallet.RecoverLegacyKeccak256Hash(strHash, strSig)
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	log.Infof("public key [%s]", strPubKey)
	strAddress, err := wallet.PublicKey2Address(strPubKey)
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	log.Infof("address [%s]", strAddress)
}

func VerifySignatureKeccak256() {
	strHash := "924a14c42641d860962d8f19f6e4e147631b3f4b8745b57b07552db07a78f04f"
	strSig := "a580661c2356f8ce6be68204148b266f268b6b491f2eef1b3f05cdddad76ba7c6afdc629c3f6c4aefc8d5964984d58ba7f8aa6c3d1aadf30f0871d1758222eeb1c" //metamask
	strPubKey, err := wallet.RecoverKeccak256Hash(strHash, strSig)
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	log.Infof("public key [%s]", strPubKey)
	strAddress, err := wallet.PublicKey2Address(strPubKey)
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	log.Infof("address [%s]", strAddress)
}

func WalletSignAndVerify() {
	//create a new wallet
	var wc = wallet.NewWalletEthereum(wallet.OpType_Create)
	log.Infof("[CREATE] address [%s] private key [%s] public key [%s] phrase [%s]", wc.GetAddress(), wc.GetPrivateKey(), wc.GetPublicKey(), wc.GetPhrase())

	////recover a wallet from phrase
	//var wr = wallet.NewWalletEthereum(wallet.OpType_Recover, wc.GetPhrase())
	//log.Infof("[RECOVER] address [%s] private key [%s] public key [%s] phrase [%s]", wr.GetAddress(), wr.GetPrivateKey(), wr.GetPublicKey(), wr.GetPhrase())
	////load a wallet from full info
	//var wl = wallet.NewWalletEthereum(wallet.OpType_Load, wc.GetAddress(), wc.GetPrivateKey(), wc.GetPublicKey(), wc.GetPhrase())
	//log.Infof("[LOAD] address [%s] private key [%s] public key [%s] phrase [%s]", wl.GetAddress(), wl.GetPrivateKey(), wl.GetPublicKey(), wl.GetPhrase())
	//
	////new a wallet from public key, you just can verify signature
	//var wv = wallet.NewWalletEthereum(wallet.OpType_Verify, wc.GetPublicKey())
	//log.Infof("[VERIFY] public key [%s]", wv.GetPublicKey())

	var strHelloWorld = "helloworld world"
	strMsgHash, strSignature, err := wc.SignText([]byte(strHelloWorld))
	if err != nil {
		log.Errorf("sign failed [%s]", err.Error())
		panic(err.Error())
	}
	log.Infof("msg hash [%s] signature [%s]", strMsgHash, strSignature)
	if !wc.VerifyText([]byte(strHelloWorld), strSignature) {
		log.Errorf("verify signature failed")
		panic("verify signature failed")
	} else {
		log.Infof("verify signature ok")
	}

	strPubKeyRecover, err := wallet.RecoverLegacyKeccak256Hash(strMsgHash, strSignature)
	if err != nil {
		log.Errorf("RecoverPubKey error [%s]", err)
		return
	}
	if strPubKeyRecover != wc.GetPublicKey() {
		log.Errorf("public key [%s] not match [%s]", strPubKeyRecover, wc.GetPublicKey())
		return
	}
	log.Infof("public key recover [%s] ok", strPubKeyRecover)
}
