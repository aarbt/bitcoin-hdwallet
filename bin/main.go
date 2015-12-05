package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"

	"github.com/runeaune/hdkeys"
)

var seedHex = flag.String("seed", "", "hex encoded random seed between 16 and 64 bytes.")

func main() {
	flag.Parse()

	seed, err := hex.DecodeString(*seedHex)
	if err != nil {
		log.Fatal(err)
	}
	if len(seed) == 0 {
		seed = make([]byte, 32)
		rand.Read(seed)
	}

	key := hdkeys.NewMasterKey(seed)

	log.Println(key.SerializeEncode())
	log.Println(key.PublicKeyHashEncode())
}
