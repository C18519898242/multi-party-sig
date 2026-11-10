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
	chainCode := make([]byte, 32)
	imports := runImportProtocol(t, ids, "import-key", func(id party.ID) protocol.StartFunc {
		return ImportKey(id, ids, shares[id], publicKey, chainCode, nil)
	})

	configs := make(map[party.ID]*Config, len(ids))
	for id, result := range imports {
		cfg := result.(*Config)
		require.True(t, cfg.PublicPoint().Equal(expected))
		require.Equal(t, chainCode, []byte(cfg.ChainKey))
		require.True(t, cfg.CanSign(ids))
		require.False(t, cfg.CanSign(ids[:2]))
		configs[id] = cfg
	}
	presigs := runImportProtocol(t, ids, "presign-imported-key", func(id party.ID) protocol.StartFunc {
		return Presign(configs[id], ids, nil)
	})
	digest := sha256.Sum256([]byte("presign with imported key"))
	signatures := runImportProtocol(t, ids, "presign-online-imported-key", func(id party.ID) protocol.StartFunc {
		return PresignOnline(configs[id], presigs[id].(*ecdsa.PreSignature), digest[:], nil)
	})
	for _, result := range signatures {
		require.True(t, result.(*ecdsa.Signature).Verify(expected, digest[:]))
	}
}

func TestImportKeyRestoresAndRefreshesGeneratedChainCode(t *testing.T) {
	ids := party.IDSlice{"alice", "bob", "carol"}
	group := curve.Secp256k1{}
	shares, publicKey, err := SplitPrivateKey(bytes.Repeat([]byte{1}, 32), ids)
	require.NoError(t, err)
	expected := group.NewPoint()
	require.NoError(t, expected.UnmarshalBinary(publicKey))
	imports := runImportProtocol(t, ids, "import-with-generated-chain-code", func(id party.ID) protocol.StartFunc {
		roster := ids
		if id == "bob" {
			roster = party.IDSlice{"carol", "alice", "bob"}
		}
		return ImportKey(id, roster, shares[id], publicKey, nil, nil)
	})
	first := imports[ids[0]].(*Config)
	chainCode := first.ChainKey
	require.Len(t, chainCode, 32)
	configs := make(map[party.ID]*Config, len(ids))
	for id, result := range imports {
		cfg := result.(*Config)
		require.Equal(t, first.RID, cfg.RID)
		require.Equal(t, chainCode, cfg.ChainKey)
		encoded, err := cfg.MarshalBinary()
		require.NoError(t, err)
		restored := EmptyConfig(group)
		require.NoError(t, restored.UnmarshalBinary(encoded))
		require.Equal(t, chainCode, restored.ChainKey)
		require.True(t, restored.PublicPoint().Equal(expected))
		configs[id] = restored
	}
	refreshed := runImportProtocol(t, ids, "refresh-imported-key", func(id party.ID) protocol.StartFunc {
		return Refresh(configs[id], nil)
	})
	digest := sha256.Sum256([]byte("sign after restoring and refreshing"))
	signatures := runImportProtocol(t, ids, "sign-refreshed-key", func(id party.ID) protocol.StartFunc {
		cfg := refreshed[id].(*Config)
		require.Equal(t, chainCode, cfg.ChainKey)
		return Sign(cfg, ids, digest[:], nil)
	})
	for _, result := range signatures {
		require.True(t, result.(*ecdsa.Signature).Verify(expected, digest[:]))
	}
}

func TestSplitPrivateKeyGeneratesFreshContributions(t *testing.T) {
	ids := party.IDSlice{"a", "b", "c"}
	privateKey := bytes.Repeat([]byte{1}, 32)
	shares, _, err := SplitPrivateKey(privateKey, ids)
	require.NoError(t, err)
	otherShares, _, err := SplitPrivateKey(privateKey, ids)
	require.NoError(t, err)
	group := curve.Secp256k1{}
	sum := group.NewScalar()
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		share := group.NewScalar()
		require.NoError(t, share.UnmarshalBinary(shares[id]))
		require.False(t, share.IsZero())
		require.False(t, seen[string(shares[id])])
		seen[string(shares[id])] = true
		require.NotEqual(t, shares[id], otherShares[id])
		sum.Add(share)
	}
	encoded, err := sum.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, privateKey, encoded)
}

func TestImportKeyRejectsPublicKeyMismatch(t *testing.T) {
	ids := party.IDSlice{"alice", "bob", "carol"}
	privateKey := make([]byte, 32)
	privateKey[31] = 42
	shares, publicKey, err := SplitPrivateKey(privateKey, ids)
	require.NoError(t, err)
	group := curve.Secp256k1{}
	wrongPublicKey, err := group.NewBasePoint().MarshalBinary()
	require.NoError(t, err)
	badShare := group.NewScalar()
	require.NoError(t, badShare.UnmarshalBinary(shares["alice"]))
	tampered, err := badShare.Negate().MarshalBinary()
	require.NoError(t, err)
	for _, tc := range []struct {
		name         string
		publicKey    []byte
		contribution []byte
	}{
		{"wrong expected key", wrongPublicKey, shares["alice"]},
		{"wrong contribution", publicKey, tampered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handlers := make(map[party.ID]*protocol.MultiHandler, len(ids))
			for _, id := range ids {
				contribution := shares[id]
				if id == "alice" {
					contribution = tc.contribution
				}
				h, err := protocol.NewMultiHandler(ImportKey(id, ids, contribution, tc.publicKey, nil, nil), []byte(tc.name))
				require.NoError(t, err)
				handlers[id] = h
			}
			runImportTestHandlers(ids, handlers)
			for _, h := range handlers {
				result, err := h.Result()
				require.Nil(t, result)
				require.ErrorContains(t, err, "public key mismatch")
			}
		})
	}
}

func TestImportKeyRejectsInvalidInputs(t *testing.T) {
	ids := party.IDSlice{"a", "b", "c"}
	privateKey := bytes.Repeat([]byte{1}, 32)
	for _, invalid := range [][]byte{nil, make([]byte, 32), bytes.Repeat([]byte{0xff}, 32)} {
		_, _, err := SplitPrivateKey(invalid, ids)
		require.Error(t, err)
	}
	for _, invalid := range []party.IDSlice{ids[:2], {"a", "b", "c", "d"}, {"a", "a", "c"}, {"a", "\x00a", "c"}, {"a", "\x00", "c"}, {"a", "b", "\xff"}} {
		_, _, err := SplitPrivateKey(privateKey, invalid)
		require.Error(t, err)
	}
	shares, publicKey, err := SplitPrivateKey(privateKey, ids)
	require.NoError(t, err)
	_, err = ImportKey("a", ids, shares["a"], publicKey, nil, nil)(nil)
	require.Error(t, err)
	sessionID := []byte("invalid-input")
	_, err = ImportKey("other", ids, shares["a"], publicKey, nil, nil)(sessionID)
	require.ErrorContains(t, err, "cmp import: self ID")
	for _, contribution := range [][]byte{make([]byte, 32), make([]byte, 33)} {
		_, err = ImportKey("a", ids, contribution, publicKey, nil, nil)(sessionID)
		require.Error(t, err)
	}
	_, err = ImportKey("a", ids, shares["a"], publicKey, make([]byte, 33), nil)(sessionID)
	require.Error(t, err)
	for _, invalid := range [][]byte{append([]byte{4}, publicKey[1:]...), make([]byte, 65), append([]byte{2}, bytes.Repeat([]byte{0xff}, 32)...)} {
		_, err = ImportKey("a", ids, shares["a"], invalid, nil, nil)(sessionID)
		require.Error(t, err)
	}
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
	otherChain, err := ImportKey("z", ids, contributions["z"], publicKey, make([]byte, 32), nil)(sessionID)
	require.NoError(t, err)
	require.NotEqual(t, first.SSID(), otherChain.SSID())
}

func runImportProtocol(t *testing.T, ids party.IDSlice, sessionID string, start func(party.ID) protocol.StartFunc) map[party.ID]interface{} {
	t.Helper()
	handlers := make(map[party.ID]*protocol.MultiHandler, len(ids))
	for _, id := range ids {
		h, err := protocol.NewMultiHandler(start(id), []byte(sessionID))
		require.NoError(t, err)
		handlers[id] = h
	}
	runImportTestHandlers(ids, handlers)
	results := make(map[party.ID]interface{}, len(ids))
	for id, h := range handlers {
		result, err := h.Result()
		require.NoError(t, err)
		results[id] = result
	}
	return results
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
