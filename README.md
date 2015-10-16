# Hierarchical Deterministic Keys
Hierarchical deterministic key derivation library, as described in BIP-0032. Supports BIP-0043 and BIP-0044 (Multi-Account hierarchy).

Generating a new master key:
```
seed := make([]byte, 32)
rand.Read(seed)
key := hdkeys.NewMasterKey(seed)
```

Serializing / exporting a key:
```
encoded := key.SerializeEncode()
fmt.Println(encoded) // eg. "xprv9s21ZrQH143K2PXAG98v5UhDdHawJG1DsV8DJrc76VTV7n2c8ZyN3VDkEAPBKcBL7BQssWqPFgVZN5rktZZSd8j37PtzLaGx7tVNWtF8i5S"
```

Deriving a child key:
```
child, err := k.Child(0)
hardenedChild, err := k.Child(0 + 1<<31)
```

Getting the public version of a private key:
```
pubKey := prvKey.Public()
fmt.Println(pubKey.IsPublic()) // "true"
```

Getting the address of a key:
```
addr := key.PublicKeyHashEncode()
fmt.Println(addr) // "1AvqrWZtrKgJEJh1PStbHLMQ1Bk7N22GyJ"
```

# BIP-0044
Generating BIP-0044 style addresses at the format `m / purpose' / coin_type' / account' / change / address_index`

```
key, err := masterKey.Chain("m/44'/0'/0'/0/0")
```
