package bitset

import (
	"fmt"
	"math/big"

	"filippo.io/bigmod"
)

const blockSize = 33

var modulus *bigmod.Modulus

func init() {
	var err error
	x := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	y := new(big.Int).Exp(big.NewInt(2), big.NewInt(96), nil)
	mod := new(big.Int).Add(x, y)
	mod.Sub(mod, big.NewInt(1))
	modulus, err = bigmod.NewModulus(mod.Bytes())
	if err != nil {
		panic(fmt.Sprintf("bitset: failed to initialize modulus: %v", err))
	}
	if size := (modulus.BitLen() + 7) / 8; size != blockSize {
		panic(fmt.Sprintf("bitset: modulus size does not match BlockSize: %d", size))
	}
}

type BitSet struct {
	len uint64
	set []byte
}

func New(len uint64) *BitSet {
	blocks := (len + 255) / 256
	b := make([]byte, blockSize*blocks)
	return &BitSet{len: len, set: b}
}

func NewFromBytes(b []byte, len uint64) *BitSet {
	return &BitSet{len: len, set: b}
}

func (b *BitSet) Bytes() []byte {
	return b.set
}

func (b *BitSet) Set(i uint64) error {
	if i >= b.len {
		return fmt.Errorf("index out of bounds: %d", i)
	}
	block := ((i+1)+255)/256 - 1
	b.set[uint64(len(b.set))-i>>3-block-1] |= 1 << (i & 7)
	return nil
}

func (b *BitSet) BitsAt(i, n uint64) ([]byte, error) {
	if i >= b.len {
		return nil, fmt.Errorf("starting index out of bounds: %d", i)
	}
	if (i + n - 1) >= b.len {
		return nil, fmt.Errorf("ending index out of bounds: %d", i)
	}
	out := make([]byte, max((n+7)/8, 2))
	for read := range n {
		si := i + read
		block := ((si+1)+255)/256 - 1
		sb := b.set[uint64(len(b.set))-si>>3-block-1]
		if (sb>>(si&7))&1 != 0 {
			out[uint64(len(out))-read>>3-1] |= 1 << (read & 7)
		}
	}
	return out, nil
}

var bigZero = big.NewInt(0)

func (b *BitSet) Neg() error {
	blocks := (b.len + 255) / 256
	for i := range blocks {
		num, err := bigmod.NewNat().SetBytes(b.set[i*blockSize:(i+1)*blockSize], modulus)
		if err != nil {
			return fmt.Errorf("unusable bitset block %d: %w", i, err)
		}
		neg, err := bigmod.NewNat().SetBytes(bigZero.Bytes(), modulus)
		if err != nil {
			return fmt.Errorf("unusable zero value: %w", err)
		}
		copy(b.set[i*blockSize:(i+1)*blockSize], neg.Sub(num, modulus).Bytes(modulus))
	}
	return nil
}
