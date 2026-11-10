package cmp

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/keygen"
)

// SplitPrivateKey splits a 32-byte secp256k1 private key into three single-use
// additive contributions and returns the compressed public key. Each party
// supplies its contribution to ImportKey to generate its signing share.
func SplitPrivateKey(privateKey []byte, participants []party.ID) (map[party.ID][]byte, []byte, error) {
	return keygen.SplitPrivateKey(privateKey, participants)
}

// ImportKey starts a 3-of-3 CMP session for an existing secp256k1 key. Each
// party provides its own contribution and the same independently verified
// compressed public key. A supplied 32-byte BIP32 chain code is preserved as
// given. A nil or empty chain code is generated during import. All parties
// must use the same unique, non-empty session ID. Returns *cmp.Config on success.
func ImportKey(selfID party.ID, participants []party.ID, contribution, publicKey, chainCode []byte, pl *pool.Pool) protocol.StartFunc {
	return keygen.Import(selfID, participants, contribution, publicKey, chainCode, pl)
}
