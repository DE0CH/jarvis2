package h2c

import (
	"encoding/hex"
	"testing"
)

// RFC 9380 J.1.1 (P256_XMD:SHA-256_SSWU_RO_)
func TestRFC9380Vectors(t *testing.T) {
	dst := []byte("QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_")
	for _, v := range []struct{ msg, x, y string }{
		{"", "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4", "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415"},
		{"abc", "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f", "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e"},
		{"abcdef0123456789", "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80", "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3"},
	} {
		pt, err := HashToCurve([]byte(v.msg), dst)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(pt[1:33]) + hex.EncodeToString(pt[33:]); got != v.x+v.y {
			t.Fatalf("msg %q: %s", v.msg, got)
		}
	}
}

func TestObjectKeysDiffer(t *testing.T) {
	seen := map[string]bool{}
	for _, o := range []string{"sink", "source-00", "source-01"} {
		for _, u := range []string{"signing", "encryption"} {
			k := ObjectKey(o, u)
			if seen[k] || k != ObjectKey(o, u) {
				t.Fatal(o, u)
			}
			seen[k] = true
		}
	}
}
