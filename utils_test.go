package wallet

import (
	"github.com/civet148/log"
	"testing"
)

func Test_VerifySignatureLegacyKeccak256(t *testing.T) {
	strHash := "924a14c42641d860962d8f19f6e4e147631b3f4b8745b57b07552db07a78f04f"
	strSig := "0df090d0600ad3387c0a8aa61ba9bf5127f88dc6fa2cb8e6d41b354f1f1cd9dd0ea40c7fccec2edcfd7c4296897a34a048084377b7cb6aa1f7b7b15015b5c2d100" //data app
	strPubKey, err := RecoverLegacyKeccak256Hash(strHash, strSig)
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	log.Infof("public key [%s]", strPubKey)
	strAddress, err := PublicKey2Address(strPubKey)
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	log.Infof("address [%s]", strAddress)
}

func Test_VerifySignatureKeccak256(t *testing.T) {
	strHash := "924a14c42641d860962d8f19f6e4e147631b3f4b8745b57b07552db07a78f04f"
	strSig := "a580661c2356f8ce6be68204148b266f268b6b491f2eef1b3f05cdddad76ba7c6afdc629c3f6c4aefc8d5964984d58ba7f8aa6c3d1aadf30f0871d1758222eeb1c" //metamask
	strPubKey, err := RecoverKeccak256Hash(strHash, strSig)
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	log.Infof("public key [%s]", strPubKey)
	strAddress, err := PublicKey2Address(strPubKey)
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	log.Infof("address [%s]", strAddress)
}

func Test_VerifySignatureSolana(t *testing.T) {
	//base58 encoded signature
	sig := "2amhinnUjRMef8aNMKKhGCf4odSR3q9Tq2SjYjvFePN6ZmStF5EbNmfdsqssXe4XjXn6Nidu1Sg4MKyo5UPVWQgf"
	//base58 encoded public key
	addr := "2vKtu3nW1TS6iPvJPK8R88B5QfDrwJDwwB11Uu1CN9o7"
	//base64 encoded message
	msg := "AgEBBByE1Y6EqCJKsr7iEupU6lsBHtBdtI4SK3yWMCFA0iEKeFPgnGmtp+1SIX1Ak+sN65iBaR7v4Iim5m1OEuFQTgi9N57UnhNpCNuUePaTt7HJaFBmyeZB3deXeKWVudpY3gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWVECK/n3a7QR6OKWYR4DuAVjS6FXgZj82W0dJpSIPnEBAwQAAgEDDAIAAABAQg8AAAAAAA=="
	ok, err := VerifySignatureSolana(addr, msg, sig)
	if err != nil {
		log.Errorf("%s", err)
		return
	}
	if ok {
		log.Infof("signature verify [OK]")
	} else {
		log.Errorf("signature verify [FAILED]")
	}
}

func Test_WalletSignAndVerify(t *testing.T) {
	//create a new wallet
	var wc = NewWalletEthereum(OpType_Create)
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

	strPubKeyRecover, err := RecoverLegacyKeccak256Hash(strMsgHash, strSignature)
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
