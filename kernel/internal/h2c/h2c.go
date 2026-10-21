// Package h2c: the keys of objects nobody holds (sources and the sink, DESIGN "Target design"). Each is a P-256 point
// hashed from the object's name (RFC 9380, P256_XMD:SHA-256_SSWU_RO_), so its discrete log is unknown to everyone:
// a grant on a source or the sink seals to a key nobody can open, and anyone can recompute it from the name.
package h2c

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"

	"filippo.io/nistec"
)

// DST: the domain separation tag of every object key
const DST = "jarvis2-object-v1"

var (
	curve = elliptic.P256().Params()
	p     = curve.P
	a     = new(big.Int).Sub(p, big.NewInt(3))  // A = -3
	z     = new(big.Int).Sub(p, big.NewInt(10)) // Z = -10 (RFC 9380 8.2)
)

// expandXMD: expand_message_xmd with SHA-256 (RFC 9380 5.3.1)
func expandXMD(msg, dst []byte, n int) ([]byte, error) {
	ell := (n + 31) / 32
	if ell > 255 || n > 65535 || len(dst) > 255 {
		return nil, errors.New("expand_message_xmd: input too long")
	}
	dstPrime := append(append([]byte{}, dst...), byte(len(dst)))
	h := sha256.New()
	h.Write(make([]byte, 64)) // Z_pad
	h.Write(msg)
	h.Write([]byte{byte(n >> 8), byte(n), 0})
	h.Write(dstPrime)
	b0 := h.Sum(nil)
	h.Reset()
	h.Write(b0)
	h.Write([]byte{1})
	h.Write(dstPrime)
	bi := h.Sum(nil)
	out := append([]byte{}, bi...)
	for i := 2; i <= ell; i++ {
		x := make([]byte, 32)
		for j := range x {
			x[j] = b0[j] ^ bi[j]
		}
		h.Reset()
		h.Write(x)
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		bi = h.Sum(nil)
		out = append(out, bi...)
	}
	return out[:n], nil
}

// hashToField: two field elements, L = 48 (RFC 9380 5.2)
func hashToField(msg, dst []byte) ([2]*big.Int, error) {
	b, err := expandXMD(msg, dst, 96)
	if err != nil {
		return [2]*big.Int{}, err
	}
	return [2]*big.Int{new(big.Int).Mod(new(big.Int).SetBytes(b[:48]), p), new(big.Int).Mod(new(big.Int).SetBytes(b[48:]), p)}, nil
}

func mod(x *big.Int) *big.Int { return x.Mod(x, p) }

func gx(x *big.Int) *big.Int { // x³ + Ax + B
	t := new(big.Int).Exp(x, big.NewInt(3), p)
	t.Add(t, new(big.Int).Mul(a, x))
	t.Add(t, curve.B)
	return mod(t)
}

// mapToCurve: simplified SWU (RFC 9380 6.6.2); not constant time — every input here is public
func mapToCurve(u *big.Int) []byte {
	u2 := mod(new(big.Int).Mul(u, u))
	zu2 := mod(new(big.Int).Mul(z, u2))
	den := mod(new(big.Int).Add(new(big.Int).Mul(zu2, zu2), zu2)) // Z²u⁴ + Zu²
	negBoverA := mod(new(big.Int).Mul(new(big.Int).Neg(curve.B), new(big.Int).ModInverse(a, p)))
	var x1 *big.Int
	if den.Sign() == 0 {
		x1 = mod(new(big.Int).Mul(curve.B, new(big.Int).ModInverse(mod(new(big.Int).Mul(z, a)), p)))
	} else {
		x1 = mod(new(big.Int).Mul(negBoverA, new(big.Int).Add(big.NewInt(1), new(big.Int).ModInverse(den, p))))
	}
	x, y := x1, new(big.Int).ModSqrt(gx(x1), p)
	if y == nil {
		x = mod(new(big.Int).Mul(zu2, x1))
		y = new(big.Int).ModSqrt(gx(x), p)
	}
	if u.Bit(0) != y.Bit(0) {
		y = mod(new(big.Int).Neg(y))
	}
	out := make([]byte, 65)
	out[0] = 4
	x.FillBytes(out[1:33])
	y.FillBytes(out[33:])
	return out
}

// HashToCurve: the uncompressed point of msg under dst (P256_XMD:SHA-256_SSWU_RO_)
func HashToCurve(msg, dst []byte) ([]byte, error) {
	u, err := hashToField(msg, dst)
	if err != nil {
		return nil, err
	}
	q0, err := nistec.NewP256Point().SetBytes(mapToCurve(u[0]))
	if err != nil {
		return nil, err
	}
	q1, err := nistec.NewP256Point().SetBytes(mapToCurve(u[1]))
	if err != nil {
		return nil, err
	}
	return nistec.NewP256Point().Add(q0, q1).Bytes(), nil // P-256's cofactor is 1
}

// ObjectKey: an object's signing or encryption key (use "signing" or "encryption"), base64 like every key
func ObjectKey(object, use string) string {
	pt, err := HashToCurve([]byte("jarvis2 "+object+" "+use), []byte(DST))
	if err != nil {
		panic(err) // the inputs are short: expand_message_xmd can't refuse them
	}
	return base64.StdEncoding.EncodeToString(pt)
}
