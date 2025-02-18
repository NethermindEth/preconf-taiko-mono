package txlistfetcher

import (
	"context"
	"crypto/sha256"

	"github.com/ethereum-optimism/optimism/op-service/eth"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/log"

	"github.com/taikoxyz/taiko-mono/packages/taiko-client/bindings/metadata"
	"github.com/taikoxyz/taiko-mono/packages/taiko-client/pkg"
	"github.com/taikoxyz/taiko-mono/packages/taiko-client/pkg/rpc"
)

// BlobFetcher is responsible for fetching the txList blob from the L1 block sidecar.
type BlobFetcher struct {
	l1Beacon   *rpc.BeaconClient
	dataSource *rpc.BlobDataSource
}

// NewBlobTxListFetcher creates a new BlobFetcher instance based on the given rpc client.
func NewBlobTxListFetcher(l1Beacon *rpc.BeaconClient, ds *rpc.BlobDataSource) *BlobFetcher {
	return &BlobFetcher{l1Beacon, ds}
}

// FetchOntake implements the TxListFetcher interface.
func (d *BlobFetcher) FetchOntake(
	ctx context.Context,
	_ *types.Transaction,
	meta metadata.TaikoBlockMetaDataOntake,
) ([]byte, error) {
	if !meta.GetBlobUsed() {
		return nil, pkg.ErrBlobUnused
	}

	// Fetch the L1 block sidecars.
	sidecars, err := d.dataSource.GetBlobs(
		ctx,
		meta.GetProposedAt(),
		meta.GetBlobHash(),
	)
	if err != nil {
		return nil, err
	}

	log.Info(
		"Fetch sidecars",
		"blockNumber", meta.GetRawBlockHeight(),
		"sidecars", len(sidecars),
	)

	// Compare the blob hash with the sidecar's kzg commitment.
	for i, sidecar := range sidecars {
		log.Info(
			"Block sidecar",
			"index", i,
			"KzgCommitment", sidecar.KzgCommitment,
			"blobHash", meta.GetBlobHash(),
		)

		commitment := kzg4844.Commitment(common.FromHex(sidecar.KzgCommitment))
		if kzg4844.CalcBlobHashV1(sha256.New(), &commitment) == meta.GetBlobHash() {
			blob := eth.Blob(common.FromHex(sidecar.Blob))
			bytes, err := blob.ToData()
			if err != nil {
				return nil, err
			}

			if meta.GetBlobTxListLength() == 0 {
				return bytes, nil
			}

			b, err := sliceTxList(meta.GetBlockID(), bytes, meta.GetBlobTxListOffset(), meta.GetBlobTxListLength())
			if err != nil {
				log.Warn("Invalid txlist offset and size in metadata", "blockID", meta.GetBlockID(), "err", err)
				return []byte{}, nil
			}
			return b, nil
		}
	}

	return nil, pkg.ErrSidecarNotFound
}

// FetchPacaya implements the TxListFetcher interface.
func (d *BlobFetcher) FetchPacaya(
	ctx context.Context,
	tx *types.Transaction,
	meta metadata.TaikoBatchMetaDataPacaya,
) ([]byte, error) {
	if len(meta.GetBlobHashes()) == 0 {
		return nil, pkg.ErrBlobUnused
	}

	var b []byte
	// Fetch the L1 block sidecars.
	sidecars, err := d.dataSource.GetBlobs(
		ctx,
		meta.GetProposedAt(),
		meta.GetBlobHashes()[0],
	)
	if err != nil {
		return nil, err
	}

	log.Info(
		"Fetch sidecars",
		"blockNumber", meta.GetRawBlockHeight(),
		"sidecars", len(sidecars),
	)

	for _, blobHash := range meta.GetBlobHashes() {
		// Compare the blob hash with the sidecar's kzg commitment.
		for j, sidecar := range sidecars {
			log.Debug(
				"Block sidecar",
				"index", j,
				"KzgCommitment", sidecar.KzgCommitment,
				"blobHash", blobHash,
			)

			commitment := kzg4844.Commitment(common.FromHex(sidecar.KzgCommitment))
			if kzg4844.CalcBlobHashV1(sha256.New(), &commitment) == blobHash {
				blob := eth.Blob(common.FromHex(sidecar.Blob))
				bytes, err := blob.ToData()
				if err != nil {
					return nil, err
				}

				b = append(b, bytes...)
			}
		}
	}
	if len(b) == 0 {
		return nil, pkg.ErrSidecarNotFound
	}

	return sliceTxList(meta.GetBatchID(), b, meta.GetTxListOffset(), meta.GetTxListSize())
}
