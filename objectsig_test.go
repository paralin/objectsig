package objectsig

import (
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p-crypto"
)

func TestSignature(t *testing.T) {
	data := make([]byte, 50)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err.Error())
	}

	privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		t.Fatal(err.Error())
	}

	sig, err := NewSignature(privKey, data)
	if err != nil {
		t.Fatal(err.Error())
	}

	if err := sig.Verify(privKey.GetPublic(), data); err != nil {
		t.Fatal(err.Error())
	}
}
