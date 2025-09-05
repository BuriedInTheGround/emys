package emys_test

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strings"
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

func lemmasFromFile(name string) []string {
	text, err := os.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("failed to read lemmas file %q: %v", name, err))
	}
	lemmas := make([]string, 0, 5000)
	for lemma := range strings.SplitSeq(string(text), "\n") {
		if len(lemma) == 0 {
			continue
		}
		lemmas = append(lemmas, lemma)
	}
	slices.Sort(lemmas)
	return slices.Compact(lemmas)
}

// Top 5000 most frequent English lemmas (4380 unique words) as of 2025-08-28.
// Source: https://www.wordfrequency.info/samples.asp
var lemmas = lemmasFromFile("testdata/top-lemmas.txt")

func generateFile(words int) string {
	f := make([]string, words)
	for i := range words {
		f[i] = lemmas[rand.IntN(len(lemmas))]
	}
	return strings.Join(f, " ")
}

func generateFileHistory(id uint64, size int) []sse.Change[uint64] {
	changes := make([]sse.Change[uint64], size)
	var old []byte
	for i := range size {
		new := []byte(generateFile(20))
		changes[i] = sse.Change[uint64]{
			FileID: id,
			Diff:   emys.Diff(old, new),
		}
		old = new
	}
	return changes
}

func TestPrepareBenchmarkStates(t *testing.T) {
	if testing.Short() {
		t.Skip("skip synthetic dataset preparation")
	}
	key := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	nonce := []byte("USER FOR BENCHMARKS ONLY")

	for _, files := range []uint64{1000, 10_000, 100_000, 1_000_000} {
		for _, trigrams := range []uint16{3, 15} {
			name := fmt.Sprintf("files=%d/trigrams=%d", files, trigrams)
			t.Run(name, func(t *testing.T) {
				config := &emys.Config{
					MaxFiles:          files,
					MaxSearchTrigrams: trigrams,
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

				changes := make([]sse.Change[uint64], files)
				for i := range files {
					changes[i] = generateFileHistory(i, 1)[0]
				}
				utoks, err := client.Update(changes...)
				if err != nil {
					t.Fatal(err)
				}
				if err := server.ResolveUpdates(utoks...); err != nil {
					t.Fatal(err)
				}

				clientState, err := client.State()
				if err != nil {
					t.Fatal(err)
				}
				cf, err := os.Create(fmt.Sprintf("testdata/state-client-%d-%d", files, trigrams))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := cf.Write(clientState); err != nil {
					t.Fatal(err)
				}
				if err := cf.Close(); err != nil {
					t.Fatal(err)
				}

				serverState, err := server.State()
				if err != nil {
					t.Fatal(err)
				}
				sf, err := os.Create(fmt.Sprintf("testdata/state-server-%d-%d", files, trigrams))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := sf.Write(serverState); err != nil {
					t.Fatal(err)
				}
				if err := sf.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func BenchmarkSearch(b *testing.B) {
	key := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	nonce := []byte("USER FOR BENCHMARKS ONLY")

	for _, files := range []uint64{1000, 10_000, 100_000, 1_000_000} {
		for _, trigrams := range []uint16{3, 15} {
			name := fmt.Sprintf("files=%d/trigrams=%d", files, trigrams)
			b.Run(name, func(b *testing.B) {
				config := &emys.Config{
					MaxFiles:          files,
					MaxSearchTrigrams: trigrams,
					SearchThreshold:   0.75,
				}
				client, err := emys.NewClient(key, nonce, config)
				if err != nil {
					b.Fatal(err)
				}
				server, err := emys.NewServer(config)
				if err != nil {
					b.Fatal(err)
				}

				clientState, err := os.ReadFile(fmt.Sprintf("testdata/state-client-%d-%d", files, trigrams))
				if err != nil {
					b.Fatal(err)
				}
				if err := client.LoadState(clientState); err != nil {
					b.Fatal(err)
				}

				serverState, err := os.ReadFile(fmt.Sprintf("testdata/state-server-%d-%d", files, trigrams))
				if err != nil {
					b.Fatal(err)
				}
				if err := server.LoadState(serverState); err != nil {
					b.Fatal(err)
				}

				query := &emys.Query{}
				line := generateFile(50)
				size := min(int(trigrams)+2, len(line))
				query.Text = string(line[:size])

				for b.Loop() {
					stok, err := client.Search(query)
					if err != nil {
						b.Fatal(err)
					}
					result, err := server.ResolveSearch(stok)
					if err != nil {
						b.Fatal(err)
					}
					_, err = client.OpenResult(query, result)
					if err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkUpdate(b *testing.B) {
	key := []byte("YELLOW SUBMARINE, BLACK WIZARDRY")
	nonce := []byte("USER FOR BENCHMARKS ONLY")

	for _, files := range []uint64{1000, 10_000, 100_000, 1_000_000} {
		for _, trigrams := range []uint16{3, 15} {
			name := fmt.Sprintf("files=%d/trigrams=%d", files, trigrams)
			b.Run(name, func(b *testing.B) {
				config := &emys.Config{
					MaxFiles:          files,
					MaxSearchTrigrams: trigrams,
					SearchThreshold:   0.75,
				}
				client, err := emys.NewClient(key, nonce, config)
				if err != nil {
					b.Fatal(err)
				}
				server, err := emys.NewServer(config)
				if err != nil {
					b.Fatal(err)
				}

				clientState, err := os.ReadFile(fmt.Sprintf("testdata/state-client-%d-%d", files, trigrams))
				if err != nil {
					b.Fatal(err)
				}
				if err := client.LoadState(clientState); err != nil {
					b.Fatal(err)
				}

				serverState, err := os.ReadFile(fmt.Sprintf("testdata/state-server-%d-%d", files, trigrams))
				if err != nil {
					b.Fatal(err)
				}
				if err := server.LoadState(serverState); err != nil {
					b.Fatal(err)
				}

				n := rand.IntN(int(files))
				changes := generateFileHistory(uint64(n), 10_000)
				i := 0
				for b.Loop() {
					utok, err := client.Update(changes[i%int(files)])
					if err != nil {
						b.Fatal(err)
					}
					err = server.ResolveUpdates(utok...)
					if err != nil {
						b.Fatal(err)
					}
					i++
				}
			})
		}
	}
}
