package hdkeys

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"math/rand"
	"strings"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/bitcoin-crypto/bitelliptic"
	"github.com/aarbt/mnemonic"

	"testing"
)

func harden(i uint32) uint32 {
	return i + 1<<31
}

func randomData(r *rand.Rand, bytes int) []byte {
	data := make([]byte, bytes)
	for i, _ := range data {
		data[i] = byte(r.Uint32() % 256)
	}
	return data
}

type Test struct {
	key *Key
	pub string
	prv string
}

func TestSerializeParseCompressedLeadingZeros(t *testing.T) {
	// This key is carefully selected to create an X value with 0x00 as the first byte.
	key, _ := hex.DecodeString(
		"62e64ee507fedb901b5f2010f039a6a872c6c6eaaf41108f34141f7b1d24f7dd")
	x, y := bitelliptic.S256().ScalarBaseMult(key)

	// The expected X is 31 bytes, missing its leading 0x00 byte.
	expectedX, _ := hex.DecodeString(
		"f3cfae3aa223e058cfb4e139035191616e60443521baaaa541e08247a5208a")
	if !bytes.Equal(x.Bytes(), expectedX) {
		t.Errorf("Didn't get expected X: got %x, expected %x.",
			x.Bytes(), expectedX)
	}
	data := SerializeCompact(point{x, y})
	p := ParseCompact(data)
	if x.Cmp(p.x) != 0 {
		t.Errorf("X changed: got %v, expected %v.", p.x, x)
	}
	if y.Cmp(p.y) != 0 {
		t.Errorf("Y changed: got %v, expected %v.", p.y, y)
	}
}

func TestSerializeParseCompressedRandom(t *testing.T) {
	// Deterministic source of "random" numbers.
	r := rand.New(rand.NewSource(0))
	for i := 0; i < 25; i++ {
		// Compressed storage is unable to represent arbitrary Ys,
		// every (x,y) point must correspond to a point on the curve
		// or we won't be able to recover it.
		key := randomData(r, 32)
		x, y := bitelliptic.S256().ScalarBaseMult(key)
		if !bitelliptic.S256().IsOnCurve(x, y) {
			t.Fatalf("Point (%v,%v) isn't on the curve.", x, y)
		}
		data := SerializeCompact(point{x, y})
		p := ParseCompact(data)
		if x.Cmp(p.x) != 0 {
			t.Errorf("Test %d: X changed: got %v, expected %v (random data: %x).",
				i, p.x, x, key)
		}
		if y.Cmp(p.y) != 0 {
			t.Errorf("Test %d: Y changed: got %v, expected %v (random data: %x).",
				i, p.y, y, key)
		}
	}
}

func TestSerializeParseUncompressedLeadingZeros(t *testing.T) {
	// Uncompressed storage is able to represent arbitrary Ys.
	xB, _ := hex.DecodeString("000002030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	yB, _ := hex.DecodeString("ff0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0000")
	x := new(big.Int).SetBytes(xB)
	y := new(big.Int).SetBytes(yB)
	data := SerializeUncompressed(point{x, y})
	X, Y, _ := ParseUncompressed(data)
	if x.Cmp(X) != 0 {
		t.Errorf("X changed: got %v, expected %v.", X, x)
	}
	if y.Cmp(Y) != 0 {
		t.Errorf("Y changed: got %v, expected %v.", Y, y)
	}
}

func TestHashing(t *testing.T) {
	pub, _ := hex.DecodeString("03b9c2618c5d089bf4f6ab9849b4e364c1212c701357d6d168ddaf1e8ba55a233d")
	hashRef, _ := hex.DecodeString("d4b1fe6c3caf3e86b80a7246544c3b4a70735c2a")
	hash := RIPEMD160Hash(pub)
	if !bytes.Equal(hash, hashRef) {
		t.Errorf("Hash mismatch: got %x, expected %x.", hash, hashRef)
	}
}

func TestPrivateToPublic(t *testing.T) {
	prv, _ := hex.DecodeString("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")
	pubRef, _ := hex.DecodeString("0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6")
	hashRef := "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"

	pub := SerializeUncompressed(privateToPublic(parse256(prv)))
	if !bytes.Equal(pub, pubRef) {
		t.Errorf("Public key mismatch: got %x, expected %x.", pub, pubRef)
	}
	h, _ := base58.BitcoinCheckEncode(
		base58.BitcoinPublicKeyHashPrefix,
		RIPEMD160Hash(pub))
	if h != hashRef {
		t.Errorf("Public key hash mismatch: got %s, expected %s.", h, hashRef)
	}
}

func TestPrivateToPublic2(t *testing.T) {
	prvBytes, _ := hex.DecodeString(
		"685554a72f06aa051b03a05154355c1591e668b1948d66325952807daae9de71")
	prv := parse256(prvBytes)
	pubKey := SerializeCompact(privateToPublic(prv))
	h, _ := base58.BitcoinCheckEncode(
		base58.BitcoinPublicKeyHashPrefix,
		RIPEMD160Hash(pubKey))
	hashRef := "1LPdUu1qKXFTowobD9uB62QesdodtV2ugx"
	if h != hashRef {
		t.Errorf("Public key hash mismatch: got %s, expected %s.", h, hashRef)
	}
}

func TestSerializeParseUncompressedRandom(t *testing.T) {
	// Deterministic source of "random" numbers.
	r := rand.New(rand.NewSource(0))
	for i := 0; i < 100; i++ {
		// Uncompressed storage is able to represent arbitrary Ys.
		x := randomData(r, 32)
		y := randomData(r, 32)
		data := []byte{0x04}
		data = append(data, x...)
		data = append(data, y...)
		X, Y, _ := ParseUncompressed(data)
		Data := SerializeUncompressed(point{X, Y})
		if !bytes.Equal(data, Data) {
			t.Errorf("Data changed: got %x, expected %x.", Data, data)
		}
	}
}

func TestParseSerialize256LeadingZeros(t *testing.T) {
	master, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f")
	key := parse256(master)
	res := ser256(key)
	if !bytes.Equal(master, res) {
		t.Errorf("Resulting data doesn't match master: got %x, expected %x.",
			res, master)
	}
}

func TestParseSerialize256Random(t *testing.T) {
	// Deterministic source of "random" numbers.
	r := rand.New(rand.NewSource(0))
	for i := 0; i < 10; i++ {
		master := randomData(r, 32)
		key := parse256(master)
		res := ser256(key)
		if !bytes.Equal(master, res) {
			t.Errorf("Run %d: Resulting data doesn't match master: got %x, expected %x.",
				i, res, master)
		}
	}
}

// Test vector 1 from BIP0032
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
func TestVector1(t *testing.T) {
	var vector []Test
	master, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	// Chain m
	vector = append(vector, Test{
		key: NewPrivateKey(master),
		pub: "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
		prv: "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
	})

	// Chain m/0H
	vector = append(vector, Test{
		key: vector[0].key.ChildOrDie(harden(0)),
		pub: "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
		prv: "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
	})

	// Chain m/0H/1
	vector = append(vector, Test{
		key: vector[1].key.ChildOrDie(1),
		pub: "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
		prv: "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
	})

	// Chain m/0H/1/2H
	vector = append(vector, Test{
		key: vector[2].key.ChildOrDie(harden(2)),
		pub: "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
		prv: "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
	})

	// Chain m/0H/1/2H/2
	vector = append(vector, Test{
		key: vector[3].key.ChildOrDie(2),
		pub: "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
		prv: "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
	})

	// Chain m/0H/1/2H/2/1000000000
	vector = append(vector, Test{
		key: vector[4].key.ChildOrDie(1000000000),
		pub: "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
		prv: "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
	})

	for i, T := range vector {
		prv := base58.CheckEncodeToString(T.key.Serialize())
		pub := base58.CheckEncodeToString(T.key.Public().Serialize())

		if prv != T.prv {
			t.Errorf("Test %d: Private key mismatch: got %q, expected %q.",
				i, prv, T.prv)
		}
		if pub != T.pub {
			t.Errorf("Test %d: Public key mismatch: got %q, expected %q.",
				i, pub, T.pub)
		}
	}
}

// Test vector 2 from BIP0032
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
func TestVector2(t *testing.T) {
	var vector []Test
	master, _ := hex.DecodeString("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")

	// Chain m
	vector = append(vector, Test{
		key: NewPrivateKey(master),
		pub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
		prv: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
	})

	// Chain m/0
	vector = append(vector, Test{
		key: vector[0].key.ChildOrDie(0),
		pub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
		prv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
	})

	// Chain m/0/2147483647H
	vector = append(vector, Test{
		key: vector[1].key.ChildOrDie(harden(2147483647)),
		pub: "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
		prv: "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
	})

	// Chain m/0/2147483647H/1
	vector = append(vector, Test{
		key: vector[2].key.ChildOrDie(1),
		pub: "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
		prv: "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
	})

	// Chain m/0/2147483647H/1/2147483646H
	vector = append(vector, Test{
		key: vector[3].key.ChildOrDie(harden(2147483646)),
		pub: "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
		prv: "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
	})

	// Chain m/0/2147483647H/1/2147483646H/2
	vector = append(vector, Test{
		key: vector[4].key.ChildOrDie(2),
		pub: "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
		prv: "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
	})

	for i, T := range vector {
		prv := base58.CheckEncodeToString(T.key.Serialize())
		pub := base58.CheckEncodeToString(T.key.Public().Serialize())

		if prv != T.prv {
			t.Errorf("Test %d: Private key mismatch: got %q, expected %q.",
				i, prv, T.prv)
		}
		if pub != T.pub {
			t.Errorf("Test %d: Public key mismatch: got %q, expected %q.",
				i, pub, T.pub)
		}
	}
}

func TestPublicDerivation(t *testing.T) {
	// Deterministic source of "random" numbers.
	r := rand.New(rand.NewSource(0))

	for i := 0; i < 5; i++ {
		seed := randomData(r, 64)
		key := NewPrivateKey(seed)
		if key.IsPublic() {
			t.Fatalf("Key public when not expected to.")
		}
		key2, err := ParseEncoded(key.SerializeEncode())
		if err != nil {
			t.Fatalf("Failed to parse encoded: %v", err)
		}
		if !bytes.Equal(key.Serialize(), key2.Serialize()) {
			t.Errorf("Key changed when serialized and parsed back: "+
				"expected %x, got %x.",
				key.code, key2.code)
		}

		pub := key.Public()
		if !pub.IsPublic() {
			t.Fatalf("Key not public when expected to.")
		}
		c1 := key.ChildOrDie(uint32(i))
		c2 := pub.ChildOrDie(uint32(i))
		pub2 := c1.Public()
		if c2.SerializeEncode() != pub2.SerializeEncode() {
			t.Errorf("Different derivation paths yielded different keys: "+
				"%q vs %q.",
				c2.SerializeEncode(), pub2.SerializeEncode())
		}
	}
}

func TestPublicDerivationFail(t *testing.T) {
	// Deterministic source of "random" numbers.
	r := rand.New(rand.NewSource(1))

	seed := randomData(r, 64)
	key := NewPrivateKey(seed)
	pub := key.Public()
	c1 := key.ChildOrDie(0)
	c2 := pub.ChildOrDie(1)
	pub2 := c1.Public()
	if c2.SerializeEncode() == pub2.SerializeEncode() {
		t.Errorf("Different indexes yielded same keys: "+
			"%q vs %q.",
			c2.SerializeEncode(), pub2.SerializeEncode())
	}
}

func TestChainDerivation1(t *testing.T) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	key := NewPrivateKey(seed)
	cc, err := key.Chain("m/0H/1/2H/2/1000000000")
	if err != nil {
		t.Fatalf("Chain derivation failed: %v", err)
	}
	prv := "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
	pub := "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
	if cc.SerializeEncode() != prv || cc.Public().SerializeEncode() != pub {
		t.Errorf("Chain derivation yielded wrong result.")
	}
}

func TestChainDerivation2(t *testing.T) {
	seed := mnemonic.SeedFromWordsPassword(
		strings.Split("avoid element lobster scout spare actor page woman "+
			"clog street include proud", " "), "")
	key := NewPrivateKey(seed)
	recv, err := key.Chain("m/ 44'/ 0'/ 0'/ 0/ 0")
	if err != nil {
		t.Fatalf("Chain derivation failed: %v", err)
	}
	if recv.PublicKeyHashEncode() != "1APWnkAgU5iaiJtz7Ga7i3pGA127oQnnTG" {
		t.Errorf("Chain derivation yielded wrong result: %s",
			recv.PublicKeyHash())
	}

	change, err := key.Chain("M/44'  /0' /0 ' /1  /10")
	if err != nil {
		t.Fatalf("Chain derivation failed: %v", err)
	}
	if change.PublicKeyHashEncode() != "17pZuDHfXNLKxyA7hsd1cGrSSPtUrhnxTq" {
		t.Errorf("Chain derivation yielded wrong result: %s",
			change.PublicKeyHash())
	}
}
