package emys_test

import (
	"bytes"
	"slices"
	"testing"

	"interrato.dev/emys/internal/emys"
)

func TestDiff(t *testing.T) {
	old := []byte("Hello")
	new := []byte("こんにちわ")
	diff := emys.Diff(old, new)
	want := []byte("-Hel-ell-llo+こんに+にちわ+んにち")
	if !bytes.Equal(diff, want) {
		t.Errorf("got %q, want %q", diff, want)
	}
}

func TestParseDiff(t *testing.T) {
	old := []byte("supermassive black hole")
	new := []byte("black hole is supermassive")
	diff := emys.Diff(old, new)
	removed, inserted, err := emys.ParseDiff(diff)
	if err != nil {
		t.Fatal(err)
	}
	wantRemoved := []string{" bl", "e b", "ve "}
	wantInserted := []string{" is", " su", "e i", "is ", "le ", "s s"}
	if slices.Compare(removed, wantRemoved) != 0 {
		t.Errorf("removed: got %q, want %q", removed, wantRemoved)
	}
	if slices.Compare(inserted, wantInserted) != 0 {
		t.Errorf("inserted: got %q, want %q", inserted, wantInserted)
	}
}
