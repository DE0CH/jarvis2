package main

// The box key: planted when the box was made (a Secret only the core's namespace reads). The core signs its
// fresh public keys with it at start (IdentityText), so its identity can travel as plain text through anything
// untrusted; the app and the setup session check it against keys/box.pub.

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// SignerFromPEM: a PKCS#8 P-256 private key (the box key)
func SignerFromPEM(b []byte) (*Signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an EC key")
	}
	return &Signer{ek}, nil
}
