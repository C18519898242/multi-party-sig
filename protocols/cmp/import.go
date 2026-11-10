package cmp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/keygen"
)

const importPartyCount = 3

// SplitPrivateKey splits a 32-byte secp256k1 private key into three additive
// contributions for ImportKey and returns the compressed public key.
// Send each contribution only to its intended party over an authenticated,
// confidential channel. The import tool has access to the complete key.
func SplitPrivateKey(privateKey []byte, participants []party.ID) (map[party.ID][]byte, []byte, error) {
	if err := validateImportParticipants(participants); err != nil {
		return nil, nil, err
	}
	group := curve.Secp256k1{}
	secret := group.NewScalar()
	if err := secret.UnmarshalBinary(privateKey); err != nil {
		return nil, nil, fmt.Errorf("cmp import: invalid private key: %w", err)
	}
	if secret.IsZero() {
		return nil, nil, errors.New("cmp import: private key is zero")
	}
	publicKey, err := secret.ActOnBase().MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	first := sample.ScalarUnit(rand.Reader, group)
	remainder := group.NewScalar().Set(secret).Sub(first)
	second := sample.ScalarUnit(rand.Reader, group)
	for second.Equal(remainder) {
		second = sample.ScalarUnit(rand.Reader, group)
	}
	third := remainder.Sub(second)

	contributions := make(map[party.ID][]byte, importPartyCount)
	for i, scalar := range [...]curve.Scalar{first, second, third} {
		encoded, err := scalar.MarshalBinary()
		if err != nil {
			return nil, nil, err
		}
		contributions[participants[i]] = encoded
	}
	return contributions, publicKey, nil
}

// ImportKey starts a 3-of-3 CMP session for an existing secp256k1 key. Each
// party provides its own contribution from SplitPrivateKey, the same expected
// compressed public key, and the same optional 32-byte BIP32 chain code.
// A missing chain code is generated during import. All three parties must use
// the same unique, non-empty session ID. Returns *cmp.Config on success.
func ImportKey(selfID party.ID, participants []party.ID, contribution, publicKey, chainCode []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		if len(sessionID) == 0 {
			return nil, errors.New("cmp import: session ID is required")
		}
		if err := validateImportParticipants(participants); err != nil {
			return nil, err
		}
		if len(chainCode) != 0 && len(chainCode) != params.SecBytes {
			return nil, errors.New("cmp import: chain code must be 32 bytes")
		}
		group := curve.Secp256k1{}
		secret := group.NewScalar()
		if err := secret.UnmarshalBinary(contribution); err != nil {
			return nil, fmt.Errorf("cmp import: invalid contribution: %w", err)
		}
		if secret.IsZero() {
			return nil, errors.New("cmp import: contribution is zero")
		}
		if len(publicKey) != 33 || (publicKey[0] != 2 && publicKey[0] != 3) {
			return nil, errors.New("cmp import: expected a compressed secp256k1 public key")
		}
		expected := group.NewPoint()
		if err := expected.UnmarshalBinary(publicKey); err != nil {
			return nil, fmt.Errorf("cmp import: invalid public key: %w", err)
		}
		info := round.Info{
			ProtocolID:       "cmp/import-key",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           selfID,
			PartyIDs:         participants,
			Threshold:        importPartyCount - 1,
			Group:            group,
		}
		return keygen.StartImport(info, sessionID, pl, secret, expected, append(types.RID(nil), chainCode...))
	}
}

func validateImportParticipants(participants []party.ID) error {
	if len(participants) != importPartyCount {
		return errors.New("cmp import: exactly three participants are required")
	}
	group := curve.Secp256k1{}
	seen := make(map[string]bool, importPartyCount)
	for _, id := range participants {
		if len(id) == 0 || len(id) > 32 || !utf8.ValidString(string(id)) {
			return errors.New("cmp import: participant IDs must be valid UTF-8 of 1 to 32 bytes")
		}
		scalar := id.Scalar(group)
		encoded, err := scalar.MarshalBinary()
		if err != nil {
			return err
		}
		if scalar.IsZero() || seen[string(encoded)] {
			return errors.New("cmp import: participant IDs must map to distinct non-zero scalars")
		}
		seen[string(encoded)] = true
	}
	return nil
}
