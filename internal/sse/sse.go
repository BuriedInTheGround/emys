package sse

type Query any

type SearchToken []byte

type SearchResult []byte

type Searcher[T comparable] interface {
	Search(query Query) (SearchToken, error)
	OpenResult(query Query, result SearchResult) ([]T, error)
}

type SearchResolver interface {
	ResolveSearch(token SearchToken) (SearchResult, error)
}

type Change[T comparable] struct {
	FileID T
	Diff   []byte
}

type UpdateToken []byte

type Updater[T comparable] interface {
	Update(changes ...Change[T]) ([]UpdateToken, error)
}

type UpdateResolver interface {
	ResolveUpdates(tokens ...UpdateToken) error
}
