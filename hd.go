package hd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

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
	return RIPEMD160Hash(k.publicKey())[:4]
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
		signer.Write(k.publicKey())
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
		P := addPoints(p, ParseCompact(k.publicKey()))
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
	/*
	   4 byte: version bytes (mainnet: 0x0488B21E public, 0x0488ADE4 private;
	   			  testnet: 0x043587CF public, 0x04358394 private)
	   1 byte: depth: 0x00 for master nodes, 0x01 for level-1 derived keys, ....
	   4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
	   4 bytes: child number. This is ser32(i) for i in xi = xpar/i, with
	   	xi the key being serialized. (0x00000000 if master key) 32 bytes:
	   	the chain code
	   33 bytes: the public key or private key data (serP(K) for public
	   	keys, 0x00 || ser256(k) for private keys)
	*/

	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, k.version)
	binary.Write(&b, binary.BigEndian, k.depth)
	binary.Write(&b, binary.BigEndian, k.parent)
	binary.Write(&b, binary.BigEndian, k.index)
	b.Write(k.code)
	if k.IsPublic() {
		b.Write(k.publicKey())
	} else {
		binary.Write(&b, binary.BigEndian, byte(0x00))
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
	if k.version == BitcoinExtendedPrivateKeyVersion {
		K.version = BitcoinExtendedPublicKeyVersion
	} else if k.version == BitcoinTestnetExtendedPrivateKeyVersion {
		K.version = BitcoinTestnetExtendedPublicKeyVersion
	} else {
		panic(fmt.Sprintf("Urecognized version %x.", k.version))
	}
	return &K
}

func (k *Key) PublicAddressHash() string {
	key := SerializeUncompressed(ParseCompact(k.publicKey()))
	h, err := base58.BitcoinCheckEncode(
		base58.BitcoinPublicKeyHashPrefix,
		RIPEMD160Hash(key))
	if err != nil {
		// BitcoinCheckEncode should never fail with this input.
		panic(err.Error())
	}
	return h
}

// publicKey returns the compressed serialized public key corresponding to Key.
func (k *Key) publicKey() []byte {
	if k.pubKey == nil {
		k.pubKey = SerializeCompact(privateToPublic(k.prvKey))
	}
	return k.pubKey
}
