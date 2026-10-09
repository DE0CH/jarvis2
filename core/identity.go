package main

// The core's identity in a form Deyao reads: 8 words from the BIP39 English list (words.txt, sha256
// 2f5eed53…dbda), the first 88 bits of SHA-256 over IdentityText. The app's recovery page shows the same words.

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"strings"
)

//go:embed words.txt
var wordList string

var words = strings.Fields(wordList)

func IdentityWords(signingKey, agreementKey string) string {
	h := sha256.Sum256([]byte(IdentityText(signingKey, agreementKey)))
	out := make([]string, 8)
	for i := range out {
		idx := 0
		for b := 0; b < 11; b++ {
			bit := i*11 + b
			idx = idx<<1 | int(h[bit/8]>>(7-bit%8)&1)
		}
		out[i] = words[idx]
	}
	return strings.Join(out, " ")
}

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
