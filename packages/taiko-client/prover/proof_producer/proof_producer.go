package producer

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"

	"github.com/taikoxyz/taiko-mono/packages/taiko-client/bindings/metadata"
)

var (
	errProofGenerating = errors.New("proof is generating")
	errEmptyProof      = errors.New("proof is empty")
	ErrInvalidLength   = errors.New("invalid items length")
)

// ProofRequestBody represents a request body to generate a proof.
type ProofRequestBody struct {
	Tier uint16
	Meta metadata.TaikoProposalMetaData
}

// ContestRequestBody represents a request body to generate a proof for contesting.
type ContestRequestBody struct {
	BlockID    *big.Int
	ProposedIn *big.Int
	ParentHash common.Hash
	Meta       metadata.TaikoProposalMetaData
	Tier       uint16
}

type ProofResponse struct {
	BlockID   *big.Int
	Meta      metadata.TaikoProposalMetaData
	Proof     []byte
	Opts      ProofRequestOptions
	Tier      uint16
	ProofType ProofType
}

type BatchProofs struct {
	ProofResponses     []*ProofResponse
	BatchProof         []byte
	Tier               uint16
	BlockIDs           []*big.Int
	ProofType          ProofType
	Verifier           common.Address
	PivotBatchProof    []byte
	PivotProofVerifier common.Address
	IsPacaya           bool
}

type ProofProducer interface {
	RequestProof(
		ctx context.Context,
		opts ProofRequestOptions,
		blockID *big.Int,
		meta metadata.TaikoProposalMetaData,
		requestAt time.Time,
	) (*ProofResponse, error)
	Aggregate(
		ctx context.Context,
		items []*ProofResponse,
		requestAt time.Time,
	) (*BatchProofs, error)
	// RequestCancel @dev this function would be deprecated after Pacaya fork
	RequestCancel(
		ctx context.Context,
		opts ProofRequestOptions,
	) error
	// Tier @dev this function would be deprecated after Pacaya fork
	Tier() uint16
}
