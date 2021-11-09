# go wallet
golang blockchain wallet wrapper 

- generate address, phrase, private key, public key
- sign and verify message

# example

```go
import (
	"github.com/civet148/go-wallet"
	"github.com/civet148/log"
)

func main() {

	//create a new wallet
	var wc = wallet.NewWalletEthereum()
	log.Infof("[WALLET CREATE] address [%s] private key [%s] public key [%s] phrase [%s]", wc.GetAddress(), wc.GetPrivateKey(), wc.GetPublicKey(), wc.GetPhrase())

	//recover a wallet from phrase
	var wr = wallet.NewWalletEthereum(wc.GetPhrase())
	log.Infof("[WALLET RECOVER] address [%s] private key [%s] public key [%s] phrase [%s]", wr.GetAddress(), wr.GetPrivateKey(), wr.GetPublicKey(), wr.GetPhrase())

	//load a wallet from address, private key, public key and phrase (if you only have a public key, you just can verify signature)
	var wl = wallet.NewWalletEthereum(wc.GetAddress(), "", wc.GetPublicKey(), "")
	log.Infof("[WALLET LOAD] address [%s] private key [%s] public key [%s] phrase [%s]", wl.GetAddress(), wl.GetPrivateKey(), wl.GetPublicKey(), wl.GetPhrase())

	var strHelloWorld = "hello world"
	strSigned, err := wc.SignText([]byte(strHelloWorld))
	if err != nil {
		log.Errorf("sign failed [%s]", err.Error())
		panic(err.Error())
	}
	log.Infof("signature [%s]", strSigned)
	if !wl.VerifyText([]byte(strHelloWorld), strSigned) {
		log.Errorf("verify signature failed")
		panic("verify signature failed")
	} else {
		log.Infof("verify signature ok")
	}
}

```