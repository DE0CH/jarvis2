package kernel

// Cryptography every kernel part shares, all P-256 (the only curve the iPhone's Secure Enclave has), the same formats
// as the core's (core/crypto.go):
//   - signing: ECDSA P-256 / SHA-256, base64 DER signatures over the exact payload bytes (SignedDoc);
//   - sealing to one public key: ephemeral ECDH + HKDF-SHA256 + AES-256-GCM (Sealed).
// Points travel as base64 of the 65-byte uncompressed X9.63 encoding (CryptoKit's x963Representation).

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

// ---- signing ----------------------------------------------------------------------------------

type Signer struct{ key *ecdsa.PrivateKey }

func NewSigner() (*Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{k}, nil
}

// SignerFromPEM: a PKCS#8 P-256 private key (a part's own key, mounted from a Secret)
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

// PEM: the private key as PKCS#8 PEM (key files, test vectors)
func (s *Signer) PEM() []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(s.key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func (s *Signer) Sign(payload []byte) (string, error) {
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		return "", err
	}
	return B64.EncodeToString(sig), nil
}

// PublicKey: base64 of the uncompressed point
func (s *Signer) PublicKey() string {
	b, _ := s.key.PublicKey.ECDH()
	return B64.EncodeToString(b.Bytes())
}

// ParsePoint: a base64 uncompressed P-256 point, checked on the curve
func ParsePoint(raw string) (*ecdh.PublicKey, error) {
	b, err := B64.DecodeString(raw)
	if err != nil || len(b) != 65 {
		return nil, errors.New("not a base64 65-byte P-256 point")
	}
	return ecdh.P256().NewPublicKey(b)
}

func parseSigningKey(raw string) (*ecdsa.PublicKey, error) {
	pk, err := ParsePoint(raw)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pk) // ecdh -> ecdsa via PKIX: the same point
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

// Verify: a DER signature by pubRaw over payload
func Verify(pubRaw string, payload []byte, sigB64 string) bool {
	pk, err := parseSigningKey(pubRaw)
	if err != nil {
		return false
	}
	sig, err := B64.DecodeString(sigB64)
	if err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(pk, h[:], sig)
}

// ---- the envelope -----------------------------------------------------------------------------

// SignedDoc: every document — the exact JSON text and a signature over it
type SignedDoc struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// ID: what documents name each other by — hex sha256 of the payload
func (d SignedDoc) ID() string { return SHA256Hex(d.Payload) }

func SHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Sign: v as JSON, signed by s
func Sign(s *Signer, v any) (SignedDoc, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return SignedDoc{}, err
	}
	sig, err := s.Sign(b)
	if err != nil {
		return SignedDoc{}, err
	}
	return SignedDoc{Payload: string(b), Sig: sig}, nil
}

// Open: d's payload into out, only if pubRaw signed it, decoded strictly (no unknown fields)
func Open(pubRaw string, d SignedDoc, out any) error {
	if pubRaw == "" || !Verify(pubRaw, []byte(d.Payload), d.Sig) {
		return errors.New("bad signature")
	}
	return strictJSON([]byte(d.Payload), out)
}

// ---- sealing to one public key -------------------------------------------------------------------

func KDF(secret []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

func GCMSeal(key, plain, aad []byte) []byte {
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return append(nonce, g.Seal(nil, nonce, plain, aad)...)
}

func GCMOpen(key, sealed, aad []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("sealed data too short")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}

type Sealed struct {
	E    string `json:"e"`    // ephemeral public key
	Data string `json:"data"` // AES-GCM(nonce || ciphertext) under HKDF(x(e·R), info)
}

func SealTo(recipientRaw string, plain []byte, info string) (Sealed, error) {
	r, err := ParsePoint(recipientRaw)
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
	return Sealed{E: B64.EncodeToString(e.PublicKey().Bytes()), Data: B64.EncodeToString(GCMSeal(KDF(x, info), plain, nil))}, nil
}

func OpenSealed(priv *ecdh.PrivateKey, s Sealed, info string) ([]byte, error) {
	e, err := ParsePoint(s.E)
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
	return GCMOpen(KDF(x, info), d, nil)
}
