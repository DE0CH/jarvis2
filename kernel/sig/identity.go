package sig

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"strings"
)

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// Identity: a component's fresh keys, signed by the box key when it starts, so its identity travels as plain text
// through the untrusted router and anyone checks it against keys/box.pub
type Identity struct {
	Role         string `json:"role"`
	SigningKey   string `json:"signingKey"`
	AgreementKey string `json:"agreementKey"`
	BoxSig       string `json:"boxSig"`
}

// IdentityText: what the box key signs for a role
func IdentityText(role, signing, agreement string) string {
	return "jarvis2-kernel-" + role + "-identity " + signing + " " + agreement
}

// Component: a running component's keys
type Component struct {
	Role      string
	Signer    *Signer
	Agreement *ecdh.PrivateKey
	Identity  Identity
}

// NewComponent: fresh keys for role, vouched for by the box key
func NewComponent(role string, box *Signer) (*Component, error) {
	s, err := NewSigner()
	if err != nil {
		return nil, err
	}
	ag, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	agPub := B64.EncodeToString(ag.PublicKey().Bytes())
	bs, err := box.Sign([]byte(IdentityText(role, s.PublicKey(), agPub)))
	if err != nil {
		return nil, err
	}
	return &Component{Role: role, Signer: s, Agreement: ag, Identity: Identity{role, s.PublicKey(), agPub, bs}}, nil
}

// CheckIdentity: the identity is the box key's for that role
func CheckIdentity(id Identity, role, boxPub string) error {
	if id.Role != role || strings.ContainsAny(id.SigningKey+id.AgreementKey, " \n") {
		return fmt.Errorf("not a %s identity", role)
	}
	if !Verify(boxPub, []byte(IdentityText(role, id.SigningKey, id.AgreementKey)), id.BoxSig) {
		return fmt.Errorf("the %s identity isn't signed by the box key", role)
	}
	return nil
}
