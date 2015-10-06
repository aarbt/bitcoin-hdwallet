package hd

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/aarbt/bitcoin-crypto/bitecdsa"
	"github.com/aarbt/bitcoin-crypto/bitelliptic"
	"golang.org/x/crypto/ripemd160"
)

type point struct {
	x, y *big.Int
}

func RIPEMD160Hash(data []byte) []byte {
	first := sha256.Sum256(data)
	hasher := ripemd160.New()
	hasher.Write(first[:])
	return hasher.Sum(nil)
}

func ser256(key *big.Int) []byte {
	b := key.Bytes()
	if len(b) == 32 {
		return b
	}
	// Pad short data with leading zeros.
	padding := 32 - len(b)
	data := make([]byte, 32)
	copy(data[0+padding:32], b)
	return data
}

func parse256(b []byte) *big.Int {
	if len(b) != 32 {
		panic(fmt.Sprintf("Data \"%x\" isn't 32 bytes.", b))
	}
	return new(big.Int).SetBytes(b)
}

func SerializeCompact(p point) []byte {
	data := make([]byte, 33)
	if p.y.Bit(0) == 0 {
		// y is even.
		data[0] = 0x02
	} else {
		data[0] = 0x03
	}
	b := p.x.Bytes()
	// Pad short data with leading zeros.
	padding := 32 - len(b)
	copy(data[1+padding:33], b)
	return data
}

func ParseCompact(b []byte) point {
	if len(b) != 33 {
		panic(fmt.Sprintf("Data \"%x\" isn't 33 bytes.", b))
	}
	curve := bitelliptic.S256()

	// y = sqrt(x^3 + B) mod P
	x := new(big.Int).SetBytes(b[1:33])
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	y2 := new(big.Int).Add(x3, curve.B)
	y2.Mod(y2, curve.P)

	// sqrt(a) = a^((P+1)/4)
	e := big.NewInt(1)
	e = e.Add(e, curve.P)
	e = e.Div(e, big.NewInt(4))
	y := y2.Exp(y2, e, curve.P)

	switch b[0] {
	case 0x02:
		// y should be even.
		if y.Bit(0) == 1 {
			y = y.Sub(curve.P, y)
		}
	case 0x03:
		// y should be odd.
		if y.Bit(0) == 0 {
			y = y.Sub(curve.P, y)
		}
	default:
		// TODO consider panicking if functions is private.
		return point{}
	}
	return point{x, y}
}

func addInts(a, b *big.Int) *big.Int {
	i := a.Add(a, b)
	i.Mod(i, bitelliptic.S256().N)
	return i
}

func privateToPublic(d *big.Int) point {
	key := bitecdsa.NewKeyFromInt(bitelliptic.S256(), d)
	return point{key.X, key.Y}
}

func addPoints(a, b point) point {
	x, y := bitelliptic.S256().Add(a.x, a.y, b.x, b.y)
	return point{x, y}
}

// ParseUncompressed parses a 65 bytes uncompressed public address into a (X,Y)
// point on the curve.
func ParseUncompressed(d []byte) (*big.Int, *big.Int, error) {
	if len(d) != 65 {
		return nil, nil, fmt.Errorf("Input has wrong length %d (expected 65).", len(d))
	}
	if d[0] != 0x04 {
		return nil, nil, fmt.Errorf("Input has wrong prefix 0x%x (expected 0x04).", d[0])
	}
	return new(big.Int).SetBytes(d[1:33]), new(big.Int).SetBytes(d[33:65]), nil
}

// SerializeUncompressed serializes a point on the curve into a 65 byte
// long byte array.
func SerializeUncompressed(p point) []byte {
	X := p.x.Bytes()
	Y := p.y.Bytes()

	// Pad leading zeros for short integers.
	paddingX := 32 - len(X)
	paddingY := 32 - len(Y)

	b := make([]byte, 65)
	b[0] = 0x04
	copy(b[1+paddingX:33], X)
	copy(b[33+paddingY:65], Y)
	return b
}

func keyIsValid(i *big.Int) bool {
	if i.Sign() != 0 && i.Cmp(bitelliptic.S256().N) < 0 {
		return true
	}
	return false
}
