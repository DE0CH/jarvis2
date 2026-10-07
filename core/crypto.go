package main

// Cryptography of the core, all P-256 (the only curve the iPhone's Secure Enclave has):
//   - signing: ECDSA P-256 / SHA-256, DER signatures over the exact payload bytes;
//   - a store's data key is wrapped to the COMBINED public key P + K (phone + core): unwrapping needs
//     the phone's share p·E and the core's share k·E — Diffie–Hellman with the recipient split in two;
//   - sealing to one public key (a machine, a pending unlock): ephemeral ECDH + HKDF-SHA256 + AES-256-GCM.
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
	"errors"
	"fmt"
	"math/big"

	"filippo.io/nistec"
)

var b64 = base64.StdEncoding

// ---- signing --------------------------------------------------------------------------------

type Signer struct{ key *ecdsa.PrivateKey }

func NewSigner() (*Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{k}, nil
}

func (s *Signer) Sign(payload []byte) (string, error) {
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, h[:])
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(sig), nil
}

// PublicKey: base64 of the uncompressed point
func (s *Signer) PublicKey() string {
	b, _ := s.key.PublicKey.ECDH()
	return b64.EncodeToString(b.Bytes())
}

func parseSigningKey(raw string) (*ecdsa.PublicKey, error) {
	b, err := b64.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	pk, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return nil, err
	}
	// ecdh -> ecdsa via the PKIX encoding (both are the same point)
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	any, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	k, ok := any.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return k, nil
}

// VerifyWith: a DER signature by `pubRaw` over payload
func VerifyWith(pubRaw string, payload []byte, sigB64 string) bool {
	pk, err := parseSigningKey(pubRaw)
	if err != nil {
		return false
	}
	sig, err := b64.DecodeString(sigB64)
	if err != nil {
		return false
	}
	h := sha256.Sum256(payload)
	return ecdsa.VerifyASN1(pk, h[:], sig)
}

// ---- points ---------------------------------------------------------------------------------

func point(raw []byte) (*nistec.P256Point, error) { return nistec.NewP256Point().SetBytes(raw) }

// AddPoints: P + Q, uncompressed
func AddPoints(a, b []byte) ([]byte, error) {
	p, err := point(a)
	if err != nil {
		return nil, err
	}
	q, err := point(b)
	if err != nil {
		return nil, err
	}
	return nistec.NewP256Point().Add(p, q).Bytes(), nil
}

// ScalarMult: k·P, uncompressed
func ScalarMult(k []byte, raw []byte) ([]byte, error) {
	p, err := point(raw)
	if err != nil {
		return nil, err
	}
	r, err := nistec.NewP256Point().ScalarMult(p, k)
	if err != nil {
		return nil, err
	}
	return r.Bytes(), nil
}

// pointsWithX: the two points whose x-coordinate is x (the Enclave's key agreement returns only x)
func pointsWithX(x []byte) ([][]byte, error) {
	if len(x) != 32 {
		return nil, errors.New("x must be 32 bytes")
	}
	curve := elliptic.P256().Params()
	X := new(big.Int).SetBytes(x)
	// y² = x³ − 3x + b (mod p)
	y2 := new(big.Int).Exp(X, big.NewInt(3), curve.P)
	y2.Sub(y2, new(big.Int).Mul(big.NewInt(3), X))
	y2.Add(y2, curve.B)
	y2.Mod(y2, curve.P)
	y := new(big.Int).ModSqrt(y2, curve.P)
	if y == nil {
		return nil, errors.New("x is not on the curve")
	}
	out := [][]byte{}
	for _, yy := range []*big.Int{y, new(big.Int).Sub(curve.P, y)} {
		b := make([]byte, 65)
		b[0] = 4
		X.FillBytes(b[1:33])
		yy.FillBytes(b[33:])
		out = append(out, b)
	}
	return out, nil
}

func xOf(p []byte) []byte { return p[1:33] }

// ---- symmetric --------------------------------------------------------------------------------

func kdf(secret []byte, info string) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, info, 32)
	if err != nil {
		panic(err)
	}
	return k
}

func gcmSeal(key, plain, aad []byte) []byte {
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	return append(nonce, g.Seal(nil, nonce, plain, aad)...)
}

func gcmOpen(key, sealed, aad []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(block)
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, errors.New("sealed data too short")
	}
	return g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
}

// ---- sealing to one public key (machine keys, pending unlocks) ---------------------------------

type Sealed struct {
	E    string `json:"e"`    // ephemeral public key
	Data string `json:"data"` // AES-GCM(nonce || ciphertext) under HKDF(x(e·R), info)
}

func SealTo(recipientRaw string, plain []byte, info string) (Sealed, error) {
	rb, err := b64.DecodeString(recipientRaw)
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
	return Sealed{E: b64.EncodeToString(e.PublicKey().Bytes()), Data: b64.EncodeToString(gcmSeal(kdf(x, info), plain, nil))}, nil
}

func OpenSealed(priv *ecdh.PrivateKey, s Sealed, info string) ([]byte, error) {
	eb, err := b64.DecodeString(s.E)
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
	d, err := b64.DecodeString(s.Data)
	if err != nil {
		return nil, err
	}
	return gcmOpen(kdf(x, info), d, nil)
}

// ---- stores: data key wrapped to the combined key P + K ------------------------------------------

type WrappedKey struct {
	E       string `json:"e"`       // ephemeral public point e·G
	Wrapped string `json:"wrapped"` // AES-GCM(data key) under HKDF(x(e·(P+K)))
}

const infoStore = "jarvis2/store-data-key"

// WrapToCombined: a fresh e; secret = e·(P+K)
func WrapToCombined(phoneAgreementRaw string, coreAgreementPub []byte, dataKey []byte) (WrappedKey, error) {
	pb, err := b64.DecodeString(phoneAgreementRaw)
	if err != nil {
		return WrappedKey{}, err
	}
	combined, err := AddPoints(pb, coreAgreementPub)
	if err != nil {
		return WrappedKey{}, err
	}
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return WrappedKey{}, err
	}
	shared, err := ScalarMult(e.Bytes(), combined)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{E: b64.EncodeToString(e.PublicKey().Bytes()), Wrapped: b64.EncodeToString(gcmSeal(kdf(xOf(shared), infoStore), dataKey, nil))}, nil
}

// UnwrapWithShares: the phone's x(p·E) + the core's k → the data key (tries both points with that x)
func UnwrapWithShares(w WrappedKey, phoneShareX []byte, coreAgreement *ecdh.PrivateKey) ([]byte, error) {
	eb, err := b64.DecodeString(w.E)
	if err != nil {
		return nil, err
	}
	coreShare, err := ScalarMult(coreAgreement.Bytes(), eb)
	if err != nil {
		return nil, err
	}
	cands, err := pointsWithX(phoneShareX)
	if err != nil {
		return nil, err
	}
	wrapped, err := b64.DecodeString(w.Wrapped)
	if err != nil {
		return nil, err
	}
	for _, c := range cands {
		sum, err := AddPoints(c, coreShare)
		if err != nil {
			continue
		}
		if dk, err := gcmOpen(kdf(xOf(sum), infoStore), wrapped, nil); err == nil {
			return dk, nil
		}
	}
	return nil, fmt.Errorf("the phone's share doesn't open this store")
}
