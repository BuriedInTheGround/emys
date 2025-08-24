package emys

import "github.com/zeebo/blake3"

const emysLabel = "emys-sse.org/v1"

func deriveKey(masterKey []byte, contexts ...string) []byte {
	if len(contexts) == 0 {
		panic("key derivation without context string is insecure")
	}
	key := make([]byte, 32)
	context := canonicalize(append([]string{emysLabel}, contexts...)...)
	blake3.DeriveKey(string(context), masterKey, key)
	return key
}

func canonicalize(contexts ...string) []byte {
	var buf []byte
	count := len(contexts)
	buf = append(buf, le64(uint64(count))...)
	for _, context := range contexts {
		buf = append(buf, le64(uint64(len(context)))...)
		buf = append(buf, []byte(context)...)
	}
	return buf
}

func le64(n uint64) []byte {
	buf := make([]byte, 8)
	for i := range 8 {
		if i == 7 {
			n &= 0b0111_1111
		}
		buf[i] = byte(n & 0b1111_1111)
		n >>= 8
	}
	return buf
}
