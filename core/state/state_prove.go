package state

import (
	zkt "github.com/scroll-tech/zktrie/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
)

type TrieProve interface {
	Prove(key []byte, fromLevel uint, proofDb ethdb.KeyValueWriter) error
}

// GetSecureTrieProof handle any interface with Prove (should be a Trie in most case) and
// deliver the proof in bytes
func (s *StateDB) GetSecureTrieProof(trieProve TrieProve, key common.Hash) ([][]byte, error) {

	var proof proofList
	var err error
	if s.IsZktrie() {
		key_s, _ := zkt.ToSecureKeyBytes(key.Bytes())
		err = trieProve.Prove(key_s.Bytes(), 0, &proof)
	} else {
		err = trieProve.Prove(crypto.Keccak256(key.Bytes()), 0, &proof)
	}
	return proof, err
}
