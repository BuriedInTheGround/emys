package ahe

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"filippo.io/bigmod"
	"github.com/zeebo/blake3"
)

const BlockSize = 33

var (
	bigModulus *big.Int
	modulus    *bigmod.Modulus
)

func init() {
	var err error
	x := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	y := new(big.Int).Exp(big.NewInt(2), big.NewInt(96), nil)
	bigModulus = new(big.Int).Add(x, y)
	bigModulus.Sub(bigModulus, big.NewInt(1))
	modulus, err = bigmod.NewModulus(bigModulus.Bytes())
	if err != nil {
		panic(fmt.Sprintf("ahe: failed to initialize modulus: %v", err))
	}
	if size := (modulus.BitLen() + 7) / 8; size != BlockSize {
		panic(fmt.Sprintf("ahe: modulus size does not match BlockSize: %d", size))
	}
}

func KeyFromSeed(seed []byte, blocks uint64) (key []byte, err error) {
	if len(seed) < 32 {
		return nil, fmt.Errorf("seed size must be at least 32 bytes")
	}
	key = make([]byte, 0, BlockSize*blocks)
	h := blake3.New()
	h.Write(seed)
	xof := h.Digest()
	for range blocks {
		k, err := rand.Int(xof, bigModulus)
		if err != nil {
			panic(err)
		}
		key = append(key, k.FillBytes(make([]byte, BlockSize))...)
	}
	return
}

func Encrypt(key, plaintext []byte) (ciphertext []byte, err error) {
	if len(key) != len(plaintext) {
		return nil, fmt.Errorf("key and plaintext have different lengths")
	}
	if len(key)%BlockSize != 0 {
		return nil, fmt.Errorf("key is not a multiple of the block size")
	}
	if len(plaintext)%BlockSize != 0 {
		return nil, fmt.Errorf("plaintext is not a multiple of the block size")
	}
	ciphertext = make([]byte, len(plaintext))
	for i := range len(plaintext) / BlockSize {
		k, err := bigmod.NewNat().SetBytes(key[i*BlockSize:(i+1)*BlockSize], modulus)
		if err != nil {
			return nil, fmt.Errorf("unusable key: %w", err)
		}
		p, err := bigmod.NewNat().SetBytes(plaintext[i*BlockSize:(i+1)*BlockSize], modulus)
		if err != nil {
			return nil, fmt.Errorf("unusable plaintext: %w", err)
		}
		copy(ciphertext[i*BlockSize:(i+1)*BlockSize], p.Add(k, modulus).Bytes(modulus))
	}
	return ciphertext, nil
}

func Decrypt(key, ciphertext []byte) (plaintext []byte, err error) {
	if len(key) != len(ciphertext) {
		return nil, fmt.Errorf("key and ciphertext have different lengths")
	}
	if len(key)%BlockSize != 0 {
		return nil, fmt.Errorf("key is not a multiple of the block size")
	}
	if len(ciphertext)%BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}
	plaintext = make([]byte, len(ciphertext))
	for i := range len(ciphertext) / BlockSize {
		k, err := bigmod.NewNat().SetBytes(key[i*BlockSize:(i+1)*BlockSize], modulus)
		if err != nil {
			return nil, fmt.Errorf("unusable key: %w", err)
		}
		c, err := bigmod.NewNat().SetBytes(ciphertext[i*BlockSize:(i+1)*BlockSize], modulus)
		if err != nil {
			return nil, fmt.Errorf("unusable ciphertext: %w", err)
		}
		copy(plaintext[i*BlockSize:(i+1)*BlockSize], c.Sub(k, modulus).Bytes(modulus))
	}
	return plaintext, nil
}

func Add(dst, src []byte) error {
	if len(dst) != len(src) {
		return fmt.Errorf("dst and src have different lengths")
	}
	if len(dst)%BlockSize != 0 {
		return fmt.Errorf("dst is not a multiple of the block size")
	}
	if len(src)%BlockSize != 0 {
		return fmt.Errorf("src is not a multiple of the block size")
	}
	for i := range len(src) / BlockSize {
		out, err := bigmod.NewNat().SetBytes(dst[i*BlockSize:(i+1)*BlockSize], modulus)
		if err != nil {
			return fmt.Errorf("unusable dst: %w", err)
		}
		in, err := bigmod.NewNat().SetBytes(src[i*BlockSize:(i+1)*BlockSize], modulus)
		if err != nil {
			return fmt.Errorf("unusable src: %w", err)
		}
		copy(dst[i*BlockSize:(i+1)*BlockSize], out.Add(in, modulus).Bytes(modulus))
	}
	return nil
}
