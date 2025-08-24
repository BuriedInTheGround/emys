package emys_test

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"testing"

	"interrato.dev/emys/internal/emys"
	"interrato.dev/emys/internal/sse"
)

func TestClient_LoadState(t *testing.T) {
	key := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	nonce := []byte("THIS USER IS FOR TESTING")
	config := &emys.Config{
		MaxFiles:          1,
		MaxSearchTrigrams: 10,
		SearchThreshold:   0.75,
	}

	content := []byte("Hello, 世界")
	diff := emys.Diff(nil, content)
	change := sse.Change[uint64]{FileID: 0, Diff: diff}
	query := &emys.Query{Text: "hello"}

	client1, err := emys.NewClient(key, nonce, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client1.Update(change); err != nil {
		t.Fatal(err)
	}
	stok1, err := client1.Search(query)
	if err != nil {
		t.Fatal(err)
	}
	state, err := client1.State()
	if err != nil {
		t.Fatal(err)
	}

	client2, err := emys.NewClient(key, nonce, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := client2.LoadState(state); err != nil {
		t.Fatal(err)
	}
	stok2, err := client2.Search(query)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(stok1, stok2) {
		t.Errorf("search tokens differ: first is %x, second is %x", stok1, stok2)
	}
}

func TestEndToEnd(t *testing.T) {
	key := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	nonce := []byte("THIS USER IS FOR TESTING")
	config := &emys.Config{
		MaxFiles:          102,
		MaxSearchTrigrams: 10,
		SearchThreshold:   0.75,
	}

	client, err := emys.NewClient(key, nonce, config)
	if err != nil {
		t.Fatal(err)
	}
	server, err := emys.NewServer(config)
	if err != nil {
		t.Fatal(err)
	}

	content0 := []byte("Hello, 世界")
	diff0 := emys.Diff(nil, content0)
	change0 := sse.Change[uint64]{FileID: 0, Diff: diff0}

	content1a := []byte("Hello, Gopher!")
	diff1a := emys.Diff(nil, content1a)
	change1a := sse.Change[uint64]{FileID: 1, Diff: diff1a}

	content1b := []byte("Have fun, Gopher!")
	diff1b := emys.Diff(content1a, content1b)
	change1b := sse.Change[uint64]{FileID: 1, Diff: diff1b}

	utoks, err := client.Update(change0, change1a, change1b)
	if err != nil {
		t.Fatal(err)
	}
	err = server.ResolveUpdates(utoks...)
	if err != nil {
		t.Fatal(err)
	}

	changes := make([]sse.Change[uint64], 0, 1000)
	for i := 2; i < 102; i++ {
		changes = append(changes, generateFileHistory(uint64(i), 10)...)
	}
	utoks, err = client.Update(changes...)
	if err != nil {
		t.Fatal(err)
	}
	err = server.ResolveUpdates(utoks...)
	if err != nil {
		t.Fatal(err)
	}

	query := &emys.Query{Text: "hello"}
	stok, err := client.Search(query)
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.ResolveSearch(stok)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := client.OpenResult(query, result)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(ids, 0) {
		t.Errorf("missing expected id 0 from result set")
	}
	if slices.Contains(ids, 1) {
		t.Errorf("found unexpected id 1 in result set")
	}
}

func lines(names ...string) [][]byte {
	res := make([][]byte, 0, len(names))
	for _, name := range names {
		text, err := os.ReadFile(name)
		if err != nil {
			panic(fmt.Sprintf("failed to read corpus file %q: %v", name, err))
		}
		for line := range bytes.SplitSeq(text, []byte("\n")) {
			if len(line) > 3 {
				res = append(res, line)
			}
		}
	}
	return res
}

var lyricsLines = lines(
	"testdata/iceicebaby.txt",
	"testdata/ilcieloinunastanza.txt",
	"testdata/lapauradelbuio.txt",
	"testdata/tomsdiner.txt",
)

func generateFileHistory(id uint64, size int) []sse.Change[uint64] {
	changes := make([]sse.Change[uint64], size)
	var old []byte
	for i := range size {
		n := rand.IntN(len(lyricsLines))
		new := lyricsLines[n]
		changes[i] = sse.Change[uint64]{
			FileID: id,
			Diff:   emys.Diff(old, new),
		}
	}
	return changes
}
