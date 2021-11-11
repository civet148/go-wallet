package main

import (
	"github.com/civet148/go-wallet"
	"github.com/civet148/log"
	"net/url"
)

type Person struct {
	Name     string `json:"name"`
	Age      int    `json:"age"`
	City     string `json:"city"`
	District string `json:"district"`
	Address  string `json:"address"`
}

func main() {

	//create a new wallet
	var wc = wallet.NewWalletEthereum(wallet.OpType_Create)
	log.Infof("[CREATE] address [%s] private key [%s] public key [%s] phrase [%s]", wc.GetAddress(), wc.GetPrivateKey(), wc.GetPublicKey(), wc.GetPhrase())

	//recover a wallet from phrase
	var wr = wallet.NewWalletEthereum(wallet.OpType_Recover, wc.GetPhrase())
	log.Infof("[RECOVER] address [%s] private key [%s] public key [%s] phrase [%s]", wr.GetAddress(), wr.GetPrivateKey(), wr.GetPublicKey(), wr.GetPhrase())
	//load a wallet from full info
	var wl = wallet.NewWalletEthereum(wallet.OpType_Load, wc.GetAddress(), wc.GetPrivateKey(), wc.GetPublicKey(), wc.GetPhrase())
	log.Infof("[LOAD] address [%s] private key [%s] public key [%s] phrase [%s]", wl.GetAddress(), wl.GetPrivateKey(), wl.GetPublicKey(), wl.GetPhrase())

	//new a wallet from public key, you just can verify signature
	var wv = wallet.NewWalletEthereum(wallet.OpType_Verify, wc.GetPublicKey())
	log.Infof("[VERIFY] public key [%s]", wv.GetPublicKey())

	var strHelloWorld = "hello world"
	strSigned, err := wc.SignText([]byte(strHelloWorld))
	if err != nil {
		log.Errorf("sign failed [%s]", err.Error())
		panic(err.Error())
	}
	log.Infof("signature [%s]", strSigned)
	if !wv.VerifyText([]byte(strHelloWorld), strSigned) {
		log.Errorf("verify signature failed")
		panic("verify signature failed")
	} else {
		log.Infof("verify signature ok")
	}

	var person = &Person{
		Name:     "lory",
		Age:      18,
		City:     "NewYork",
		District: "PJ.25",
		Address:  "my hometown address",
	}
	log.Infof("struct to sign [%s]", wallet.MakeSignString(person))

	var values = url.Values{
		"name":     []string{"lory"},
		"age":      []string{"18"},
		"city":     []string{"NewYork"},
		"district": []string{"PJ.25"},
		"address":  []string{"my hometown address"},
	}
	log.Infof("url.values to sign [%s]", wallet.MakeSignString(values))

	var m = map[string]interface{}{
		"name":     "lory",
		"age":      18,
		"city":     "NewYork",
		"district": "PJ.25",
		"address":  "my hometown address",
	}
	log.Infof("map[string]interface{} to sign [%s]", wallet.MakeSignString(m))

	log.Infof("struct to sign hash [%s]", wallet.MakeSignSHA256Hex(person))
	log.Infof("url.values to sign hash [%s]", wallet.MakeSignSHA256Hex(values))
	log.Infof("map[string]interface{} to sign hash [%s]", wallet.MakeSignSHA256Hex(m))
}
