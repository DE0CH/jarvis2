// Package sig: the kernel's cryptography, all P-256 (the only curve the iPhone's Secure Enclave has), the same
// formats as core/crypto.go: ECDSA P-256 / SHA-256 DER signatures over the exact payload bytes; sealing to one public
// key = ephemeral ECDH + HKDF-SHA256 + AES-256-GCM. Points travel as base64 of the 65-byte uncompressed encoding.
package sig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
)

var B64 = base64.StdEncoding

// ---- signing ---------------------------------------------------------------------------------------------------

type Signer struct{ key *ecdsa.PrivateKey }

func NewSigner() (*Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{k}, nil
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
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return &Signer{ek}, nil
}

func (s *Signer) Sign(payload []byte) (string, error) {
	h := sha256.Sum256(payload)
	b, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		return "", err
	}
	return B64.EncodeToString(b), nil
}

// PublicKey: base64 of the uncompressed point
func (s *Signer) PublicKey() string {
	b, _ := s.key.PublicKey.ECDH()
	return B64.EncodeToString(b.Bytes())
}

func parseSigningKey(raw string) (*ecdsa.PublicKey, error) {
	b, err := B64.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return ek, nil
}

// Verify: a DER signature by pub over payload
func Verify(pub string, payload []byte, sigB64 string) bool {
	pk, err := parseSigningKey(pub)
	if err != nil {
		return false
	}
	s, err := B64.DecodeString(sigB64)
	if err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(pk, h[:], s)
}

// ---- signed documents ------------------------------------------------------------------------------------------

// Doc: a payload (exact JSON bytes as a string) and its signature
type Doc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// ID: hex sha256 of the payload
func (d Doc) ID() string {
	h := sha256.Sum256([]byte(d.Payload))
	return hex.EncodeToString(h[:])
}

// SignJSON: v marshalled and signed
func (s *Signer) SignJSON(v any) (Doc, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return Doc{}, err
	}
	g, err := s.Sign(b)
	if err != nil {
		return Doc{}, err
	}
	return Doc{Payload: string(b), Sig: g}, nil
}

// Open: the payload into v when pub signed it; unknown fields refuse it (a document means exactly what it says)
func (d Doc) Open(pub string, v any) error {
	if !Verify(pub, []byte(d.Payload), d.Sig) {
		return errors.New("bad signature")
	}
	return StrictJSON([]byte(d.Payload), v)
}

// StrictJSON: decode refusing unknown fields and trailing data
func StrictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// ---- sealing to one public key --------------------------------------------------------------------------------

type Sealed struct {
	E    string `json:"e"`    // ephemeral public key
	Data string `json:"data"` // AES-GCM(nonce || ciphertext) under HKDF(x(e·R), info)
}

func kdf(secret []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

func SealTo(recipient string, plain []byte, info string) (Sealed, error) {
	rb, err := B64.DecodeString(recipient)
	if err != nil {
		return Sealed{}, err
	}
	r, err := ecdh.P256().NewPublicKey(rb)
	if err != nil {
		return Sealed{}, err
	}
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Sealed{}, err
	}
	x, err := e.ECDH(r)
	if err != nil {
		return Sealed{}, err
	}
	block, _ := aes.NewCipher(kdf(x, info))
	g, _ := cipher.NewGCM(block)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return Sealed{E: B64.EncodeToString(e.PublicKey().Bytes()), Data: B64.EncodeToString(append(nonce, g.Seal(nil, nonce, plain, nil)...))}, nil
}

func OpenSealed(priv *ecdh.PrivateKey, s Sealed, info string) ([]byte, error) {
	eb, err := B64.DecodeString(s.E)
	if err != nil {
		return nil, err
	}
	e, err := ecdh.P256().NewPublicKey(eb)
	if err != nil {
		return nil, err
	}
	x, err := priv.ECDH(e)
	if err != nil {
		return nil, err
	}
	d, err := B64.DecodeString(s.Data)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(kdf(x, info))
	g, _ := cipher.NewGCM(block)
	if len(d) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("sealed data too short")
	}
	return g.Open(nil, d[:g.NonceSize()], d[g.NonceSize():], nil)
}
