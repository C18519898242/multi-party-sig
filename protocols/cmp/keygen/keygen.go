package keygen

import (
	"crypto/rand"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

const Rounds round.Number = 5

// StartImport runs key generation using a validated import contribution as the
// constant term and binds the expected key and chain code to the session.
func StartImport(info round.Info, sessionID []byte, pl *pool.Pool, contribution curve.Scalar, expected curve.Point, chainCode types.RID) (round.Session, error) {
	publicKey, err := expected.MarshalBinary()
	if err != nil {
		return nil, err
	}
	auxInfo := []hash.WriterToWithDomain{hash.BytesWithDomain{TheDomain: "Import public key", Bytes: publicKey}}
	if chainCode != nil {
		auxInfo = append(auxInfo, hash.BytesWithDomain{TheDomain: "Import chain code", Bytes: chainCode})
	}
	// Hash each ID separately to bind the boundaries between IDs in the roster.
	for _, id := range party.NewIDSlice(info.PartyIDs) {
		auxInfo = append(auxInfo, id)
	}
	helper, err := round.NewSession(info, sessionID, pl, auxInfo...)
	if err != nil {
		return nil, err
	}
	return &round1{
		Helper:            helper,
		ExpectedPublicKey: expected,
		PreviousChainKey:  chainCode,
		VSSSecret:         polynomial.NewPolynomial(info.Group, info.Threshold, contribution),
	}, nil
}

func Start(info round.Info, pl *pool.Pool, c *config.Config) protocol.StartFunc {
	return func(sessionID []byte) (_ round.Session, err error) {
		var helper *round.Helper
		if c == nil {
			helper, err = round.NewSession(info, sessionID, pl)
		} else {
			helper, err = round.NewSession(info, sessionID, pl, c)
		}
		if err != nil {
			return nil, fmt.Errorf("keygen: %w", err)
		}

		group := helper.Group()

		if c != nil {
			PublicSharesECDSA := make(map[party.ID]curve.Point, len(c.Public))
			for id, public := range c.Public {
				PublicSharesECDSA[id] = public.ECDSA
			}
			return &round1{
				Helper:                    helper,
				PreviousSecretECDSA:       c.ECDSA,
				PreviousPublicSharesECDSA: PublicSharesECDSA,
				PreviousChainKey:          c.ChainKey,
				VSSSecret:                 polynomial.NewPolynomial(group, helper.Threshold(), group.NewScalar()), // fᵢ(X) deg(fᵢ) = t, fᵢ(0) = 0
			}, nil
		}

		// sample fᵢ(X) deg(fᵢ) = t, fᵢ(0) = secretᵢ
		VSSConstant := sample.Scalar(rand.Reader, group)
		VSSSecret := polynomial.NewPolynomial(group, helper.Threshold(), VSSConstant)
		return &round1{
			Helper:    helper,
			VSSSecret: VSSSecret,
		}, nil

	}
}
