package wallet

const (
	ArgNumPhrase   = 1
	ArgNumFull     = 4
	DefaultBitSize = 128
)

type Wallet interface {
	Create() Wallet                                              //create a new wallet
	Recover(strPhrase string) Wallet                             //recover wallet from phrase
	SignHash(digitBytes []byte) (strSignature string, err error) //sign hash bytes (32bytes) and return a hex signature string
	VerifyHash(digitBytes []byte, strSignature string) bool      //verify hash bytes (32bytes) signature from a hex encoded signature
	SignText(text []byte) (strSignature string, err error)       //sign text bytes and return a hex signature string
	VerifyText(text []byte, strSignature string) bool            //verify text bytes signature from a hex encoded signature
	GetPrivateKey() string
	GetPublicKey() string
	GetAddress() string
	GetPhrase() string
}
