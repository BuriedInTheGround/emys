package emys

import (
	"fmt"
	"math/bits"
)

type Config struct {
	MaxFiles          uint64  // max is 2⁶⁰-1
	MaxSearchTrigrams uint16  // max is 2¹⁶-1
	SearchThreshold   float64 // (0,1]
}

func (c *Config) validate() error {
	if c.MaxFiles >= 1<<60 {
		return fmt.Errorf("maximum number of files too big: %d", c.MaxFiles)
	}
	if 256%c.fileBitLen() != 0 {
		return fmt.Errorf("invalid maximum number of search trigrams: %d", c.MaxSearchTrigrams)
	}
	if c.SearchThreshold <= 0 || c.SearchThreshold > 1 {
		return fmt.Errorf("search threshold out of range")
	}
	return nil
}

func (c *Config) fileBitLen() uint64 {
	return uint64(bits.Len16(c.MaxSearchTrigrams))
}

func (c *Config) indexBitLen() uint64 {
	return c.MaxFiles * c.fileBitLen()
}

func (c *Config) indexBlocks() uint64 {
	return (c.indexBitLen() + 255) / 256
}
