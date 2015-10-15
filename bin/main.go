package main

import (
	"encoding/hex"
	"flag"
	"log"

	"github.com/aarbt/bitcoin-base58"
	"github.com/aarbt/hdkeys"
)

var extendedKey = flag.String("extended_key", "", "")

func main() {
	flag.Parse()

	extended, err := hex.DecodeString(*extendedKey)
	if err != nil {
		log.Fatal(err)
	}
	if len(extended) != 64 {
		log.Fatalf("Extended key has wrong length %d (must be 64).",
			len(extended))
	}

	prvStr := "5KR1vxbnkT49RLW3iRGXVSCLz3C3caXfWpgifnAfrhmfN6NK2Qo"
	prvKey, prvPrefix, err := base58.BitcoinCheckDecode(prvStr)
	if err != nil || prvPrefix != base58.BitcoinPrivateKeyPrefix {
		log.Fatal(err, prvPrefix)
	}
	log.Printf("Private: %x\n", prvKey)
	pubKey, pubPrefix, err := base58.BitcoinCheckDecode("1KREnf3cDoi6oam5H75sBbUEXtrXQSWRw3")
	if err != nil || pubPrefix != base58.BitcoinPublicKeyHashPrefix {
		log.Fatal(err, pubPrefix)
	}
	log.Printf("Public hash: %x\n", pubKey)

	key := hdkeys.NewPrivateKeyFromRawData(extended)

	log.Println(key.SerializeEncode())
	log.Println(key.PublicKeyHashEncode())
}
