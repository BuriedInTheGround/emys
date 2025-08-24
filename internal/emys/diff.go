package emys

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

func Diff(old []byte, new []byte) []byte {
	var removed []string
	var inserted []string
	a := trigrams(string(old))
	b := trigrams(string(new))
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			i++
			j++
		} else if a[i] < b[j] {
			removed = append(removed, a[i])
			i++
		} else {
			inserted = append(inserted, b[j])
			j++
		}
	}
	removed = append(removed, a[i:]...)
	inserted = append(inserted, b[j:]...)
	out := make([]byte, 0, len(removed)*4+len(inserted)*4)
	if len(removed) > 0 {
		out = append(out, "-"+strings.Join(removed, "-")...)
	}
	if len(inserted) > 0 {
		out = append(out, "+"+strings.Join(inserted, "+")...)
	}
	return out
}

func ParseDiff(diff []byte) (removed []string, inserted []string, err error) {
	r := bytes.NewReader(diff)
	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		trigram := make([]rune, 3)
		for i := range 3 {
			t, _, err := r.ReadRune()
			if err == io.EOF {
				return nil, nil, fmt.Errorf("bad diff format")
			}
			trigram[i] = t
		}
		switch b {
		case '-':
			removed = append(removed, string(trigram))
		case '+':
			inserted = append(inserted, string(trigram))
		default:
			return nil, nil, fmt.Errorf("bad diff format")
		}
	}
	return
}

func trigrams(text string) []string {
	if len(text) == 0 {
		return nil
	}
	runes := []rune(text)
	if len(runes) < 3 {
		panic("emys: cannot work with less than 3 runes")
	}
	out := make(map[string]struct{}, len(runes)-2)
	for i := range len(runes) - 2 {
		trigram := string([]rune{runes[i], runes[i+1], runes[i+2]})
		out[trigram] = struct{}{}
	}
	return slices.Sorted(maps.Keys(out))
}
