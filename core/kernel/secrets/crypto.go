package secrets

// A store's data keys are wrapped to the COMBINED public key P + K (phone + secrets): unwrapping needs the phone's share
// p·E and secrets' share k·E — Diffie–Hellman with the recipient split in two (carried over from core/crypto.go).

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"filippo.io/nistec"

	"github.com/DE0CH/jarvis2/core/kernel"
)

var b64 = kernel.B64

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
	y2 := new(big.Int).Exp(X, big.NewInt(3), curve.P) // y² = x³ − 3x + b (mod p)
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

type WrappedKey struct {
	E       string `json:"e"`       // ephemeral public point e·G
	Wrapped string `json:"wrapped"` // AES-GCM(data key) under HKDF(x(e·(P+K)))
}

const infoStore = "jarvis2/store-data-key"

// UnwrapWithShares: the phone's x(p·E) + secrets' k → the data key (tries both points with that x)
func UnwrapWithShares(w WrappedKey, phoneShareX []byte, own *ecdh.PrivateKey) ([]byte, error) {
	eb, err := b64.DecodeString(w.E)
	if err != nil {
		return nil, err
	}
	ownShare, err := ScalarMult(own.Bytes(), eb)
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
		sum, err := AddPoints(c, ownShare)
		if err != nil {
			continue
		}
		if dk, err := kernel.GCMOpen(kernel.KDF(xOf(sum), infoStore), wrapped, nil); err == nil {
			return dk, nil
		}
	}
	return nil, fmt.Errorf("the phone's share doesn't open this store")
}

// WrapToPoint: what a writer does (secrets itself never wraps): the data key wrapped to a store key C = P + K — a
// one-off e, HKDF(x(e·C), "jarvis2/store-data-key"), AES-GCM
func WrapToPoint(combined, dataKey []byte) (WrappedKey, error) {
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return WrappedKey{}, err
	}
	shared, err := ScalarMult(e.Bytes(), combined)
	if err != nil {
		return WrappedKey{}, err
	}
	return WrappedKey{E: b64.EncodeToString(e.PublicKey().Bytes()), Wrapped: b64.EncodeToString(kernel.GCMSeal(kernel.KDF(xOf(shared), infoStore), dataKey, nil))}, nil
}
