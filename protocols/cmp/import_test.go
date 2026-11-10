package cmp

import (
	"bytes"
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func TestImportKeySignsWithOriginalKey(t *testing.T) {
	ids := party.IDSlice{"alice", "bob", "carol"}
	privateKey := make([]byte, 32)
	privateKey[31] = 42
	scalar := curve.Secp256k1{}.NewScalar()
	require.NoError(t, scalar.UnmarshalBinary(privateKey))
	expected := scalar.ActOnBase()
	expectedBytes, err := expected.MarshalBinary()
	require.NoError(t, err)

	shares, publicKey, err := SplitPrivateKey(privateKey, ids)
	require.NoError(t, err)
	require.Equal(t, expectedBytes, publicKey)
	chainCode := bytes.Repeat([]byte{7}, 32)
	imports := make(map[party.ID]*protocol.MultiHandler, len(ids))
	for _, id := range ids {
		imports[id], err = protocol.NewMultiHandler(ImportKey(id, ids, shares[id], publicKey, chainCode, nil), []byte("import-key"))
		require.NoError(t, err)
	}
	runImportTestHandlers(ids, imports)

	digest := sha256.Sum256([]byte("sign with imported key"))
	signers := make(map[party.ID]*protocol.MultiHandler, len(ids))
	for id, h := range imports {
		result, err := h.Result()
		require.NoError(t, err)
		cfg := result.(*Config)
		require.True(t, cfg.PublicPoint().Equal(expected))
		require.Equal(t, chainCode, []byte(cfg.ChainKey))
		require.False(t, cfg.CanSign(ids[:2]))
		signers[id], err = protocol.NewMultiHandler(Sign(cfg, ids, digest[:], nil), []byte("sign-imported-key"))
		require.NoError(t, err)
	}
	runImportTestHandlers(ids, signers)
	for _, h := range signers {
		result, err := h.Result()
		require.NoError(t, err)
		require.True(t, result.(*ecdsa.Signature).Verify(expected, digest[:]))
	}
}

func TestImportKeyRejectsWrongPublicKey(t *testing.T) {
	ids := party.IDSlice{"alice", "bob", "carol"}
	privateKey := make([]byte, 32)
	privateKey[31] = 42
	shares, _, err := SplitPrivateKey(privateKey, ids)
	require.NoError(t, err)
	wrongPublicKey, err := (curve.Secp256k1{}).NewBasePoint().MarshalBinary()
	require.NoError(t, err)

	handlers := make(map[party.ID]*protocol.MultiHandler, len(ids))
	for _, id := range ids {
		handlers[id], err = protocol.NewMultiHandler(ImportKey(id, ids, shares[id], wrongPublicKey, nil, nil), []byte("wrong-import-public-key"))
		require.NoError(t, err)
	}
	runImportTestHandlers(ids, handlers)
	for _, h := range handlers {
		result, err := h.Result()
		require.Nil(t, result)
		require.ErrorContains(t, err, "public key mismatch")
	}
}

func TestImportKeyRejectsInvalidInputs(t *testing.T) {
	ids := party.IDSlice{"a", "b", "c"}
	privateKey := bytes.Repeat([]byte{1}, 32)
	for _, invalid := range [][]byte{nil, make([]byte, 32), bytes.Repeat([]byte{0xff}, 32)} {
		_, _, err := SplitPrivateKey(invalid, ids)
		require.Error(t, err)
	}
	for _, invalid := range []party.IDSlice{ids[:2], {"a", "a", "c"}, {"a", "\x00a", "c"}, {"a", "\x00", "c"}, {"a", "b", "\xff"}} {
		_, _, err := SplitPrivateKey(privateKey, invalid)
		require.Error(t, err)
	}
	shares, publicKey, err := SplitPrivateKey(privateKey, ids)
	require.NoError(t, err)
	_, err = ImportKey("a", ids, shares["a"], publicKey, nil, nil)(nil)
	require.Error(t, err)
	_, err = ImportKey("a", ids, shares["a"], publicKey, []byte{1}, nil)([]byte("invalid-chain-code"))
	require.Error(t, err)
	publicKey[0] = 4
	_, err = ImportKey("a", ids, shares["a"], publicKey, nil, nil)([]byte("invalid-public-key"))
	require.Error(t, err)
}

func TestImportKeyBindsSessionRoster(t *testing.T) {
	ids := party.IDSlice{"a", "bc", "z"}
	privateKey := bytes.Repeat([]byte{1}, 32)
	contributions, publicKey, err := SplitPrivateKey(privateKey, ids)
	require.NoError(t, err)
	sessionID := []byte("same-request")
	first, err := ImportKey("z", ids, contributions["z"], publicKey, nil, nil)(sessionID)
	require.NoError(t, err)
	reordered, err := ImportKey("z", []party.ID{"z", "a", "bc"}, contributions["z"], publicKey, nil, nil)(sessionID)
	require.NoError(t, err)
	require.Equal(t, first.SSID(), reordered.SSID())
	other, err := ImportKey("z", []party.ID{"ab", "c", "z"}, contributions["z"], publicKey, nil, nil)(sessionID)
	require.NoError(t, err)
	require.NotEqual(t, first.SSID(), other.SSID())
}

func runImportTestHandlers(ids party.IDSlice, handlers map[party.ID]*protocol.MultiHandler) {
	network := test.NewNetwork(ids)
	var wg sync.WaitGroup
	for id, h := range handlers {
		wg.Add(1)
		go func(id party.ID, h *protocol.MultiHandler) {
			defer wg.Done()
			test.HandlerLoop(id, h, network)
		}(id, h)
	}
	wg.Wait()
}
