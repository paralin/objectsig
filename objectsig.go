package objectsig

import (
	"bytes"

	"github.com/libp2p/go-libp2p-crypto"
	mh "github.com/multiformats/go-multihash"
	"github.com/pkg/errors"
)

// NewSignature attempts to sign some data.
func NewSignature(priv crypto.PrivKey, data []byte) (*Signature, error) {
	sign, err := priv.Sign(data)
	if err != nil {
		return nil, err
	}

	pubKey := priv.GetPublic()
	pubKeyBytes, err := pubKey.Bytes()
	if err != nil {
		return nil, err
	}

	kmh, err := mh.Sum(pubKeyBytes, mh.SHA2_256, -1)
	if err != nil {
		return nil, err
	}

	return &Signature{KeyMultihash: kmh, Signature: sign}, nil
}

// MatchesPublicKey checks to see if a signature matches a public key.
// Also checked in Verify.
func (s *Signature) MatchesPublicKey(pub crypto.PubKey) error {
	pubData, err := pub.Bytes()
	if err != nil {
		return err
	}

	keyMulti, err := mh.Decode(s.GetKeyMultihash())
	if err != nil {
		return err
	}

	ourMh, err := mh.Sum(pubData, keyMulti.Code, keyMulti.Length)
	if err != nil {
		return err
	}

	// TODO: find a better way to derive digest without encoding it.
	ourMhDec, err := mh.Decode(ourMh)
	if err != nil {
		return err
	}

	if bytes.Compare(ourMhDec.Digest, keyMulti.Digest) != 0 {
		keyMultiC, err := mh.Cast(s.GetKeyMultihash())
		if err != nil {
			return err
		}

		return errors.Errorf("hash mismatch: %s != %s", ourMh.B58String(), keyMultiC.B58String())
	}

	return nil
}

// Verify checks the signature.
func (s *Signature) Verify(pub crypto.PubKey, data []byte) error {
	if err := s.MatchesPublicKey(pub); err != nil {
		return err
	}

	ok, err := pub.Verify(data, s.GetSignature())
	if err != nil {
		return err
	}

	if !ok {
		return errors.New("signature did not match")
	}

	return nil
}
