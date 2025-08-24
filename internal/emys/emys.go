package emys

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"slices"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/chacha20poly1305"
	"interrato.dev/emys/internal/ahe"
	"interrato.dev/emys/internal/ahmac"
	"interrato.dev/emys/internal/bitset"
	"interrato.dev/emys/internal/sse"
)

const (
	encryptionKeyLabel     = "index encryption"
	integrityKeyLabel      = "index integrity"
	authenticationKeyLabel = "index authentication"
	updateKeyLabel         = "update token derivation"
	clientStateKeyLabel    = "client state dump encryption"
)

type Query struct {
	Text string

	precomputedTrigrams []string
}

type Client struct {
	key          []byte
	userNonce    []byte
	integrityKey []byte
	state        map[string]clientState
	config       *Config
}

var (
	_ sse.Searcher[uint64] = &Client{}
	_ sse.Updater[uint64]  = &Client{}
)

type clientState struct {
	UpdateCount         int64
	InternalSearchToken []byte
}

func NewClient(key, userNonce []byte, config *Config) (*Client, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key size must be exaclty 32 bytes")
	}
	if len(userNonce) != 24 {
		return nil, fmt.Errorf("nonce size must be exaclty 24 bytes")
	}
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	c := &Client{
		key:          key,
		userNonce:    userNonce,
		integrityKey: ahmac.UniformKey(deriveKey(key, string(userNonce), integrityKeyLabel)),
		state:        make(map[string]clientState),
		config:       config,
	}
	return c, nil
}

func (c *Client) State() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(c.state); err != nil {
		return nil, fmt.Errorf("failed to encode client state: %w", err)
	}
	key := deriveKey(c.key, string(c.userNonce), clientStateKeyLabel)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize aead cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	ciphertext := aead.Seal(nil, nonce, buf.Bytes(), []byte("client state dump"))
	return append(nonce, ciphertext...), nil
}

func (c *Client) LoadState(state []byte) error {
	key := deriveKey(c.key, string(c.userNonce), clientStateKeyLabel)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("failed to initialize aead cipher: %w", err)
	}
	nonce := state[:aead.NonceSize()]
	ciphertext := state[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte("client state dump"))
	if err != nil {
		return fmt.Errorf("failed to decrypt client state: %w", err)
	}
	dec := gob.NewDecoder(bytes.NewBuffer(plaintext))
	if err := dec.Decode(&c.state); err != nil {
		return fmt.Errorf("failed to decode client state: %w", err)
	}
	return nil
}

func (c *Client) Search(query sse.Query) (sse.SearchToken, error) {
	searchQuery := new(Query)
	switch q := query.(type) {
	case *Query:
		searchQuery = q
	case Query:
		searchQuery = &q
	case string:
		searchQuery.Text = q
	default:
		return nil, fmt.Errorf("unexpected query type: %T", query)
	}
	if len(searchQuery.Text) < 3 {
		return nil, fmt.Errorf("query too short")
	}
	if searchQuery.precomputedTrigrams == nil {
		q := trigrams(searchQuery.Text)
		searchQuery.precomputedTrigrams = slices.DeleteFunc(q, func(trigram string) bool {
			_, ok := c.state[trigram]
			return !ok
		})
	}
	q := searchQuery.precomputedTrigrams
	if len(q) == 0 {
		return nil, nil
	}
	if len(q) > int(c.config.MaxSearchTrigrams) {
		return nil, fmt.Errorf("query too long")
	}
	stok := make([]searchToken, len(q))
	for i, trigram := range q {
		updateKey := deriveKey(c.key, string(c.userNonce), updateKeyLabel, trigram)
		stok[i] = searchToken{
			UpdateCount:         c.state[trigram].UpdateCount,
			InternalSearchToken: c.state[trigram].InternalSearchToken,
			UpdateKey:           updateKey,
		}
	}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(stok); err != nil {
		return nil, fmt.Errorf("failed to encode search token: %w", err)
	}
	return buf.Bytes(), nil
}

func (c *Client) OpenResult(query sse.Query, result sse.SearchResult) ([]uint64, error) {
	searchQuery := new(Query)
	switch q := query.(type) {
	case *Query:
		searchQuery = q
	case Query:
		searchQuery = &q
	case string:
		searchQuery.Text = q
	default:
		return nil, fmt.Errorf("unexpected query type: %T", query)
	}
	if len(searchQuery.Text) < 3 {
		return nil, fmt.Errorf("query too short")
	}
	if searchQuery.precomputedTrigrams == nil {
		q := trigrams(searchQuery.Text)
		searchQuery.precomputedTrigrams = slices.DeleteFunc(q, func(trigram string) bool {
			_, ok := c.state[trigram]
			return !ok
		})
	}
	q := searchQuery.precomputedTrigrams
	if len(q) == 0 {
		return nil, nil
	}
	if len(q) > int(c.config.MaxSearchTrigrams) {
		return nil, fmt.Errorf("query too long")
	}
	var res searchResult
	dec := gob.NewDecoder(bytes.NewBuffer(result))
	if err := dec.Decode(&res); err != nil {
		return nil, fmt.Errorf("failed to decode search result: %w", err)
	}
	encryptionKey := make([]byte, ahe.BlockSize*c.config.indexBlocks())
	authenticationKey := make([]byte, ahmac.Size)
	for _, trigram := range q {
		for count := c.state[trigram].UpdateCount; count >= 0; count-- {
			seed := deriveKey(
				c.key, string(c.userNonce), encryptionKeyLabel,
				trigram, fmt.Sprintf("%d", count),
			)
			ekey, err := ahe.KeyFromSeed(seed, c.config.indexBlocks())
			if err != nil {
				return nil, fmt.Errorf("failed to generate encryption key: %w", err)
			}
			if err := ahe.Add(encryptionKey, ekey); err != nil {
				return nil, fmt.Errorf("failed to add encryption keys: %w", err)
			}
			akey := ahmac.UniformKey(deriveKey(
				c.key, string(c.userNonce), authenticationKeyLabel,
				trigram, fmt.Sprintf("%d", count),
			))
			if err := ahmac.Add(authenticationKey, akey); err != nil {
				return nil, fmt.Errorf("failed to add authentication keys: %w", err)
			}
		}
	}
	tag, err := ahmac.MAC(c.integrityKey, authenticationKey, res.EncryptedIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to compute index tag: %w", err)
	}
	if subtle.ConstantTimeCompare(res.Tag, tag) == 0 {
		return nil, fmt.Errorf("invalid tag")
	}
	index, err := ahe.Decrypt(encryptionKey, res.EncryptedIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt index: %w", err)
	}
	bs := bitset.NewFromBytes(index, c.config.indexBitLen())
	ids := make([]uint64, 0, 32)
	usableBits := c.config.MaxFiles * c.config.fileBitLen()
	threshold := c.config.SearchThreshold * float64(len(trigrams(searchQuery.Text)))
	for i := uint64(0); i < usableBits; i += c.config.fileBitLen() {
		fileBytes, err := bs.BitsAt(i, c.config.fileBitLen())
		if err != nil {
			return nil, fmt.Errorf(
				"failed to retrieve index bits from %d to %d: %w",
				i, i+c.config.fileBitLen()-1, err,
			)
		}
		matches := binary.BigEndian.Uint16(fileBytes)
		if matches >= uint16(threshold) {
			ids = append(ids, i/c.config.fileBitLen())
		}
	}
	return ids, nil
}

func (c *Client) Update(changes ...sse.Change[uint64]) ([]sse.UpdateToken, error) {
	removed := make(map[string][]uint64)
	inserted := make(map[string][]uint64)
	for _, change := range changes {
		if change.FileID >= c.config.MaxFiles {
			return nil, fmt.Errorf("file identifier out of range: %d", change.FileID)
		}
		rem, ins, err := ParseDiff(change.Diff)
		if err != nil {
			return nil, fmt.Errorf("failed to parse diff: %w", err)
		}
		for _, trigram := range rem {
			removed[trigram] = append(removed[trigram], change.FileID)
		}
		for _, trigram := range ins {
			inserted[trigram] = append(inserted[trigram], change.FileID)
		}
	}
	out := make([]sse.UpdateToken, 0, len(removed)+len(inserted))
	for trigram, ids := range removed {
		utok, err := c.update(ids, trigram, opDel)
		if err != nil {
			return nil, err
		}
		out = append(out, utok)
	}
	for trigram, ids := range inserted {
		utok, err := c.update(ids, trigram, opAdd)
		if err != nil {
			return nil, err
		}
		out = append(out, utok)
	}
	return out, nil
}

type updateOp int

const (
	opAdd updateOp = iota
	opDel
)

func (c *Client) update(ids []uint64, trigram string, op updateOp) (sse.UpdateToken, error) {
	var count int64
	var istok []byte

	state, ok := c.state[trigram]
	if !ok {
		count = -1
		istok = make([]byte, 32)
		rand.Read(istok)
	} else {
		count = state.UpdateCount
		istok = state.InternalSearchToken
	}

	nextIstok := make([]byte, 32)
	rand.Read(nextIstok)
	c.state[trigram] = clientState{
		UpdateCount:         count + 1,
		InternalSearchToken: nextIstok,
	}

	updateKey := deriveKey(c.key, string(c.userNonce), updateKeyLabel, trigram)
	updateKeyH1 := deriveKey(updateKey, "h1")
	updateKeyH2 := deriveKey(updateKey, "h2")
	h1, err := blake3.NewKeyed(updateKeyH1)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize h1: %w", err)
	}
	h2, err := blake3.NewKeyed(updateKeyH2)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize h2: %w", err)
	}

	nextIutok := h1.Sum(nextIstok)
	maskedIstok := make([]byte, 32)
	subtle.XORBytes(maskedIstok, istok, h2.Sum(nextIstok))

	bs := bitset.New(c.config.indexBitLen())
	for _, id := range ids {
		bs.Set(id * c.config.fileBitLen())
	}
	if op == opDel {
		if err := bs.Neg(); err != nil {
			return nil, fmt.Errorf("failed to negate index: %w", err)
		}
	}

	seed := deriveKey(
		c.key, string(c.userNonce), encryptionKeyLabel,
		trigram, fmt.Sprintf("%d", count+1),
	)
	encryptionKey, err := ahe.KeyFromSeed(seed, c.config.indexBlocks())
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	encryptedIndex, err := ahe.Encrypt(encryptionKey, bs.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt index: %w", err)
	}

	authenticationKey := ahmac.UniformKey(deriveKey(
		c.key, string(c.userNonce), authenticationKeyLabel,
		trigram, fmt.Sprintf("%d", count+1),
	))
	tag, err := ahmac.MAC(c.integrityKey, authenticationKey, encryptedIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to compute index tag: %w", err)
	}

	utok := updateToken{
		NextInternalUpdateToken:   nextIutok,
		MaskedInternalSearchToken: maskedIstok,
		EncryptedIndex:            encryptedIndex,
		Tag:                       tag,
	}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(utok); err != nil {
		return nil, fmt.Errorf("failed to encode update token: %w", err)
	}
	return buf.Bytes(), nil
}

type Server struct {
	state  map[string]serverState
	config *Config
}

var (
	_ sse.SearchResolver = &Server{}
	_ sse.UpdateResolver = &Server{}
)

type serverState struct {
	MaskedInternalSearchToken []byte
	EncryptedIndex            []byte
	Tag                       []byte
}

func NewServer(config *Config) (*Server, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	s := &Server{
		state:  make(map[string]serverState),
		config: config,
	}
	return s, nil
}

func (s *Server) State() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(s.state); err != nil {
		return nil, fmt.Errorf("failed to encode server state: %w", err)
	}
	return buf.Bytes(), nil
}

func (s *Server) LoadState(state []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(state))
	if err := dec.Decode(&s.state); err != nil {
		return fmt.Errorf("failed to decode server state: %w", err)
	}
	return nil
}

func (s *Server) ResolveSearch(token sse.SearchToken) (sse.SearchResult, error) {
	var stok []searchToken
	dec := gob.NewDecoder(bytes.NewBuffer(token))
	if err := dec.Decode(&stok); err != nil {
		return nil, fmt.Errorf("failed to decode search token: %w", err)
	}
	encryptedIndexOut := make([]byte, ahe.BlockSize*s.config.indexBlocks())
	tagOut := make([]byte, ahmac.Size)
	for _, tok := range stok {
		encryptedIndexAcc := make([]byte, ahe.BlockSize*s.config.indexBlocks())
		tagAcc := make([]byte, ahmac.Size)
		updateKeyH1 := deriveKey(tok.UpdateKey, "h1")
		updateKeyH2 := deriveKey(tok.UpdateKey, "h2")
		h1, err := blake3.NewKeyed(updateKeyH1)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize h1: %w", err)
		}
		h2, err := blake3.NewKeyed(updateKeyH2)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize h2: %w", err)
		}
		istok := tok.InternalSearchToken
		var iutok []byte
		for count := tok.UpdateCount; count >= 0; count-- {
			iutok = h1.Sum(istok)
			maskedIstok := s.state[string(iutok)].MaskedInternalSearchToken
			encryptedIndex := s.state[string(iutok)].EncryptedIndex
			tag := s.state[string(iutok)].Tag
			delete(s.state, string(iutok))
			if err := ahe.Add(encryptedIndexAcc, encryptedIndex); err != nil {
				return nil, fmt.Errorf("failed to add encrypted indexes: %w", err)
			}
			if err := ahmac.Add(tagAcc, tag); err != nil {
				return nil, fmt.Errorf("failed to add tags: %w", err)
			}
			if maskedIstok == nil {
				break
			}
			subtle.XORBytes(istok, maskedIstok, h2.Sum(istok))
			h1.Reset()
			h2.Reset()
		}
		s.state[string(iutok)] = serverState{
			EncryptedIndex: encryptedIndexAcc,
			Tag:            tagAcc,
		}
		if err := ahe.Add(encryptedIndexOut, encryptedIndexAcc); err != nil {
			return nil, fmt.Errorf("failed to add accumulated encrypted indexes: %w", err)
		}
		if err := ahmac.Add(tagOut, tagAcc); err != nil {
			return nil, fmt.Errorf("failed to add accumulated tags: %w", err)
		}
	}
	res := searchResult{
		EncryptedIndex: encryptedIndexOut,
		Tag:            tagOut,
	}
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(res); err != nil {
		return nil, fmt.Errorf("failed to encode search result: %w", err)
	}
	return buf.Bytes(), nil
}

func (s *Server) ResolveUpdates(tokens ...sse.UpdateToken) error {
	for _, token := range tokens {
		var utok updateToken
		dec := gob.NewDecoder(bytes.NewBuffer(token))
		if err := dec.Decode(&utok); err != nil {
			return fmt.Errorf("failed to decode update token: %w", err)
		}
		s.state[string(utok.NextInternalUpdateToken)] = serverState{
			MaskedInternalSearchToken: utok.MaskedInternalSearchToken,
			EncryptedIndex:            utok.EncryptedIndex,
			Tag:                       utok.Tag,
		}
	}
	return nil
}

type searchToken struct {
	UpdateCount         int64
	InternalSearchToken []byte
	UpdateKey           []byte
}

type searchResult struct {
	EncryptedIndex []byte
	Tag            []byte
}

type updateToken struct {
	NextInternalUpdateToken   []byte
	MaskedInternalSearchToken []byte
	EncryptedIndex            []byte
	Tag                       []byte
}
