package main

import (
	"github.com/civet148/go-wallet"
	"github.com/civet148/log"
)

const (
	address     = "0xae020dE214129224de8d34434064f114678eA6f9"
	private_key = "e2905ff2ccaa680a53a5521843a6c6ff30a63e65864af18f5f112dcbd8ea462f"
	public_key  = "02e17dcff5febb6d37b5c3da9044d5710749eba832d18eca24c8600419cc0eac22"
	phrase      = "skin power hedgehog dash erosion jealous vocal since focus announce topic sun"
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
	VerifySignatureSHA256()
	//WalletSignAndVerify()
}

func VerifySignatureKeccak256() {
	//var strAddress = "0x0EaE3eF6CC7176553E6B45d94e9eFDE2Da7B82a5"
	//var strMsg = "Example `personal_sign` message"
	//var strSignature = "0x34850b7e36e635783df0563c7202c3ac776df59db5015d2b6f0add33955bb5c43ce35efb5ce695a243bc4c5dc4298db40cd765f3ea5612d2d57da1e4933b2f201b"
	var strAddress = "0x90Cfd4D61C9D4C63f2e4648229775ABa19ced8dF"
	var strMsg = "hello"
	var strSignature = "0x1292e758c023e0dccffb48dad52a31aa7650d599820075829a75c305703f9389065448a425cd8d59fb7885415b9b647cdeae6ffa78ddca56fbeffbae84b2cebc1c"

	var ok bool
	if ok = wallet.VerifySignatureKeccak256(strAddress, strMsg, strSignature); !ok {
		log.Errorf("verify message failed")
		return
	}
	log.Infof("verify message [%v]", ok)
}

func VerifySignatureSHA256() {
	var err error
	var strAddress = "0x446DDa728Df7c3DDa88511f9622A9f6Ccb8c3b0F"
	//var strPubKey = "03bba7449f02181303ac46b0c26ced45e1e9996044a8bfd0df3230743eb6bfb07a"
	var strMsg = "hello world"
	var strSignature = "0xa1c64956c16cb09eb9aef3a05a95b41ea0c9f70d78c5034357c135ac39fb08a337766033ad61c87bca068ad895b221dc37fda04fa181f5235e7077e5ad0aabcb00"

	var ok bool
	if ok, err = wallet.VerifySignatureSHA256(strAddress, strMsg, strSignature); err != nil {
		log.Errorf("%s", err)
		return
	}
	log.Infof("verify message [%v]", ok)
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

	var strHelloWorld = "hello world"
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
	//
	//strPubKeyRecover, err := wallet.RecoverPubKey(strMsgHash, strSignature)
	//if err != nil {
	//	log.Errorf("RecoverPubKey error [%s]", err)
	//	return
	//}
	//if strPubKeyRecover != wc.GetPublicKey() {
	//	log.Errorf("public key [%s] not match [%s]", strPubKeyRecover, wc.GetPublicKey())
	//	return
	//}
	//log.Infof("public key recover [%s] ok", strPubKeyRecover)
	//
	//var person = &Person{
	//	Name:     "lory",
	//	Age:      18,
	//	City:     "NewYork",
	//	District: "PJ.25",
	//	Address:  "my hometown address",
	//}
	//log.Infof("struct to sign [%s]", wallet.MakeSignString(person))
	//
	//var values = url.Values{
	//	"name":     []string{"lory"},
	//	"age":      []string{"18"},
	//	"city":     []string{"NewYork"},
	//	"district": []string{"PJ.25"},
	//	"address":  []string{"my hometown address"},
	//}
	//log.Infof("url.values to sign [%s]", wallet.MakeSignString(values))
	//
	//var m = map[string]interface{}{
	//	"name":     "lory",
	//	"age":      18,
	//	"city":     "NewYork",
	//	"district": "PJ.25",
	//	"address":  "my hometown address",
	//}
	//log.Infof("map[string]interface{} to sign [%s]", wallet.MakeSignString(m))
	//
	//log.Infof("struct to sign hash [%s]", wallet.MakeSignSHA256Hex(person))
	//log.Infof("url.values to sign hash [%s]", wallet.MakeSignSHA256Hex(values))
	//log.Infof("map[string]interface{} to sign hash [%s]", wallet.MakeSignSHA256Hex(m))
}
