package hd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/aarbt/bitcoin-base58"
)

const (
	BitcoinExtendedPublicKeyVersion         = 0x0488b21e
	BitcoinExtendedPrivateKeyVersion        = 0x0488ade4
	BitcoinTestnetExtendedPublicKeyVersion  = 0x043587cf
	BitcoinTestnetExtendedPrivateKeyVersion = 0x04358394
)

type Key struct {
	version uint32
	depth   uint8
	parent  []byte // 4 bytes
	index   uint32
	code    []byte
	pubKey  []byte // 33 bytes
	prvKey  *big.Int
}

func (k Key) String() string {
	return fmt.Sprintf("%d %d %x %d %x", k.version, k.depth, k.parent, k.index, k.code)
}

func NewRawKey(I []byte) *Key {
	return &Key{
		version: BitcoinExtendedPrivateKeyVersion,
		parent:  []byte{0x00, 0x00, 0x00, 0x00},
		code:    I[32:64],
		prvKey:  new(big.Int).SetBytes(I[0:32]),
	}
}

func NewPrivateKey(data []byte) *Key {
	signer := hmac.New(sha512.New, []byte("Bitcoin seed"))
	signer.Write(data)
	return NewRawKey(signer.Sum(nil))
}

func (k *Key) IsPublic() bool {
	switch k.version {
	case BitcoinExtendedPublicKeyVersion, BitcoinTestnetExtendedPublicKeyVersion:
		return true
	case BitcoinExtendedPrivateKeyVersion, BitcoinTestnetExtendedPrivateKeyVersion:
		return false
	default:
		panic(fmt.Sprintf("Urecognized version %x.", k.version))
	}
}

func (k *Key) Fingerprint() []byte {
	return RIPEMD160Hash(k.PublicKey())[:4]
}

// Child returns the child key with index i. Private keys will return private
// childs, public keys will return public childs.
func (k *Key) Child(i uint32) (*Key, error) {
	signer := hmac.New(sha512.New, k.code)
	if i >= 1<<31 {
		if k.IsPublic() {
			return nil, fmt.Errorf("Can't derive hardened child from public key.")
		} else {
			signer.Write([]byte{0x00})
			signer.Write(ser256(k.prvKey))
			binary.Write(signer, binary.BigEndian, i) // ser32
		}
	} else {
		signer.Write(k.PublicKey())
		binary.Write(signer, binary.BigEndian, i) // ser32
	}
	I := signer.Sum(nil)
	if len(I) != 64 {
		panic(fmt.Sprintf("%x isn't 64 bytes.", I))
	}

	k1 := Key{
		version: k.version,
		depth:   k.depth + 1,
		parent:  k.Fingerprint(),
		index:   i,
		code:    I[32:64],
	}
	left := parse256(I[0:32])
	if !keyIsValid(left) {
		return nil, fmt.Errorf("Invalid child, retry with different index.")
	}
	if k.IsPublic() {
		p := privateToPublic(left)
		P := addPoints(p, ParseCompact(k.PublicKey()))
		k1.pubKey = SerializeCompact(P)
	} else {
		k1.prvKey = addInts(left, k.prvKey)
	}
	return &k1, nil
}

func (k *Key) ChildOrDie(i uint32) *Key {
	c, err := k.Child(i)
	if err != nil {
		panic(err.Error())
	}
	return c
}

func Parse(d []byte) (*Key, error) {
	if len(d) != 78 {
		return nil, fmt.Errorf("Input of wrong length %d (expected 78).", len(d))
	}
	b := bytes.NewBuffer(d)
	var version uint32
	binary.Read(b, binary.BigEndian, &version)
	k := Key{version: version}
	binary.Read(b, binary.BigEndian, &k.depth)
	k.parent = make([]byte, 4)
	b.Read(k.parent)
	binary.Read(b, binary.BigEndian, &k.index)
	k.code = make([]byte, 32)
	b.Read(k.code)

	ser := make([]byte, 33)
	b.Read(ser)
	switch version {
	case BitcoinExtendedPrivateKeyVersion, BitcoinTestnetExtendedPrivateKeyVersion:
		k.prvKey = parse256(ser[1:33])
	case BitcoinExtendedPublicKeyVersion, BitcoinTestnetExtendedPublicKeyVersion:
		k.pubKey = ser
	default:
		return nil, fmt.Errorf("Input has unrecognized version %x.", version)
	}
	return &k, nil
}

// ParseEncoded parses a base58 encoded HD Key.
func ParseEncoded(s string) (*Key, error) {
	d, err := base58.CheckDecodeString(s)
	if err != nil {
		return nil, err
	}
	return Parse(d)
}

func (k *Key) Serialize() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, k.version)
	binary.Write(&b, binary.BigEndian, k.depth)
	b.Write(k.parent)
	binary.Write(&b, binary.BigEndian, k.index)
	b.Write(k.code)
	if k.IsPublic() {
		b.Write(k.PublicKey())
	} else {
		b.Write([]byte{0x00})
		b.Write(ser256(k.prvKey))
	}
	return b.Bytes()
}

// SerializeEncode serializes and base58 encodes Key.
func (k *Key) SerializeEncode() string {
	return base58.CheckEncodeToString(k.Serialize())
}

// Public returns the public version of the Key that can't be used to create
// signatures.
func (k Key) Public() *Key {
	K := k
	switch k.version {
	case BitcoinExtendedPrivateKeyVersion:
		K.version = BitcoinExtendedPublicKeyVersion
	case BitcoinTestnetExtendedPrivateKeyVersion:
		K.version = BitcoinTestnetExtendedPublicKeyVersion
	case BitcoinExtendedPublicKeyVersion, BitcoinTestnetExtendedPublicKeyVersion:
		// do nothing, return a copy.
	default:
		panic(fmt.Sprintf("Unrecognized version %x.", k.version))
	}
	return &K
}

// ExportWIF exports private key in the compressed Wallet Import Format.
func (k *Key) ExportWIF() (string, error) {
	if k.IsPublic() {
		return "", fmt.Errorf("Can't export WIF of public key.")
	}
	data := make([]byte, 34)
	prvKey := ser256(k.prvKey)
	data[0] = 0x80
	copy(data[1:33], prvKey)
	data[33] = 0x01
	return base58.CheckEncodeToString(data), nil
}

func (k *Key) PublicKeyHash() string {
	hash := RIPEMD160Hash(k.PublicKey())
	encoded, err := base58.BitcoinCheckEncode(
		base58.BitcoinPublicKeyHashPrefix, hash)
	if err != nil {
		// BitcoinCheckEncode should never fail with this input.
		panic(err.Error())
	}
	return encoded
}

func (k *Key) PublicKeyHashUncompressed() string {
	key := ParseCompact(k.PublicKey())
	ser := SerializeUncompressed(key)
	hash := RIPEMD160Hash(ser)
	encoded, err := base58.BitcoinCheckEncode(
		base58.BitcoinPublicKeyHashPrefix, hash)
	if err != nil {
		// BitcoinCheckEncode should never fail with this input.
		panic(err.Error())
	}
	return encoded
}

// PublicKey returns the compressed serialized public key corresponding to Key.
func (k *Key) PublicKey() []byte {
	if k.pubKey == nil {
		k.pubKey = SerializeCompact(privateToPublic(k.prvKey))
	}
	return k.pubKey
}

// Chain performs all the child derivations necessary to end up with the key
// described with BIP32 notations, eg. m/44'/0'/1'/0/3.
func (k *Key) Chain(chain string) (*Key, error) {
	low := strings.ToLower(chain)
	splits := strings.Split(low, "/")
	m := strings.Trim(splits[0], " ")
	if m != "m" {
		return nil, fmt.Errorf("Doesn't start with \"m\": %q.", chain)
	}
	if len(splits) == 1 {
		return k, nil
	}
	key := k
	for i, s := range splits[1:] {
		t := strings.Trim(s, " ")
		var harden uint32
		end := t[len(t)-1]
		if end == 'h' || end == '\'' {
			harden = 0x80000000
			t = t[:len(t)-1]
		}
		u, err := strconv.ParseUint(strings.Trim(t, " "), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("Couldn't parse number at position %d (%s): %v",
				i, t, err)
		}
		key, err = key.Child(uint32(u) + harden)
		if err != nil {
			return nil, fmt.Errorf("Couldn't derive child #%d (%s): %v", i, s, err)
		}
	}
	return key, nil
}
