package kernel

// Keys nobody holds: a source's and the sink's public keys are points hashed from their names, so anyone can recompute
// and check them, and nobody knows a private half. Secrets seals to whatever object a grant names; for a source or the
// sink that blob opens for nobody.
//
// Neither the standard library nor filippo.io/nistec exposes RFC 9380 hash-to-curve, so this is try-and-increment
// (DESIGN: "hash-to-curve points derived from their names"):
//
//	for counter = 0, 1, …:  x = SHA-256(name ‖ uint32_be(counter)) as a big-endian integer
//	                         skip if x ≥ p, or if x³ − 3x + b is not a square mod p
//	                         y = the square root that is even; the point is (x, y)
//
// It is not constant-time, which doesn't matter: names are public. testdata/h2c.py recomputes the points
// independently (plain Python integers) into testdata/h2c.json, which the tests compare against.

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// HashToPoint: the uncompressed point for name (65 bytes)
func HashToPoint(name string) []byte {
	c := elliptic.P256().Params()
	three := big.NewInt(3)
	for counter := uint32(0); ; counter++ {
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		h := sha256.Sum256(append([]byte(name), ctr[:]...))
		x := new(big.Int).SetBytes(h[:])
		if x.Cmp(c.P) >= 0 {
			continue
		}
		y2 := new(big.Int).Exp(x, three, c.P)
		y2.Sub(y2, new(big.Int).Mul(three, x))
		y2.Add(y2, c.B)
		y2.Mod(y2, c.P)
		y := new(big.Int).ModSqrt(y2, c.P)
		if y == nil {
			continue
		}
		if y.Bit(0) == 1 {
			y.Sub(c.P, y)
		}
		out := make([]byte, 65)
		out[0] = 4
		x.FillBytes(out[1:33])
		y.FillBytes(out[33:])
		return out
	}
}

// HashToKey: HashToPoint as a key string (base64)
func HashToKey(name string) string { return B64.EncodeToString(HashToPoint(name)) }

// The names the keys of sources and the sink are hashed from
func SinkKeyName(use string) string              { return "jarvis2 sink " + use }
func SourceKeyName(id string, use string) string { return "jarvis2 " + id + " " + use }

const (
	UseSigning    = "signing"
	UseEncryption = "encryption"
)
