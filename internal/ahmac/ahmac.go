package ahmac

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"filippo.io/bigmod"
	"github.com/zeebo/blake3"
)

const Size = 33

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
	if !bigModulus.ProbablyPrime(32) {
		panic("ahmac: modulus is not prime")
	}
	modulus, err = bigmod.NewModulus(bigModulus.Bytes())
	if err != nil {
		panic(fmt.Sprintf("ahmac: failed to initialize modulus: %v", err))
	}
	if size := (modulus.BitLen() + 7) / 8; size != Size {
		panic(fmt.Sprintf("ahmac: modulus size does not match Size: %d", size))
	}
}

func UniformKey(key []byte) []byte {
	h := blake3.New()
	h.Write(key)
	k, err := rand.Int(h.Digest(), bigModulus)
	if err != nil {
		panic(err)
	}
	return k.FillBytes(make([]byte, Size))
}

var bigZero = big.NewInt(0)

func MAC(ikey, akey, message []byte) (tag []byte, err error) {
	if len(ikey) != Size {
		return nil, fmt.Errorf("integrity key size must be exactly 33 bytes")
	}
	if len(akey) != Size {
		return nil, fmt.Errorf("authentication key size must be exactly 33 bytes")
	}

	if len(message)%Size != 0 {
		return nil, fmt.Errorf("message is not a multiple of the block size")
	}
	ik, err := bigmod.NewNat().SetBytes(ikey, modulus)
	if err != nil {
		return nil, fmt.Errorf("unusable integrity key: %w", err)
	}
	ak, err := bigmod.NewNat().SetBytes(akey, modulus)
	if err != nil {
		return nil, fmt.Errorf("unusable authentication key: %w", err)
	}
	t, err := bigmod.NewNat().SetBytes(bigZero.Bytes(), modulus)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tag: %w", err)
	}
	for i := range len(message) / Size {
		block, err := bigmod.NewNat().SetBytes(message[i*Size:(i+1)*Size], modulus)
		if err != nil {
			return nil, fmt.Errorf("unusable message: %w", err)
		}
		t.Add(block, modulus)
		t.Mul(ik, modulus)
	}
	t.Add(ak, modulus)
	return t.Bytes(modulus), nil
}

func Add(dst, src []byte) error {
	if len(dst) < Size {
		return fmt.Errorf("dst too short")
	}
	out, err := bigmod.NewNat().SetBytes(dst, modulus)
	if err != nil {
		return fmt.Errorf("unusable dst: %w", err)
	}
	in, err := bigmod.NewNat().SetBytes(src, modulus)
	if err != nil {
		return fmt.Errorf("unusable src: %w", err)
	}
	copy(dst, out.Add(in, modulus).Bytes(modulus))
	return nil
}
