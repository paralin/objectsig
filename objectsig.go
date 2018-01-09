package objectsig

import (
	"github.com/libp2p/go-libp2p-crypto"
	mh "github.com/multiformats/go-multihash"
)

// NewSignature attempts to sign some data.
func NewSignature(priv crypto.PrivKey, code uint64, data []byte) (*Signature, error) {
	sign, err := priv.Sign(data)
	if err != nil {
		return nil, err
	}

	pubKey := priv.GetPublic()
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}

	kmh, err := mh.Sum(pubKeyBytes, code, -1)
	if err != nil {
		return nil, err
	}

	return &Signature{KeyMultihash: kmh, Signature: sign}, nil
}
