package proposer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	gorilla_rcp "github.com/gorilla/rpc/v2"
	"github.com/gorilla/rpc/v2/json2"

	"github.com/ethereum-optimism/optimism/op-service/txmgr"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/errgroup"

	"github.com/taikoxyz/taiko-mono/packages/taiko-client/bindings"
	"github.com/taikoxyz/taiko-mono/packages/taiko-client/bindings/encoding"
	"github.com/taikoxyz/taiko-mono/packages/taiko-client/internal/metrics"
	"github.com/taikoxyz/taiko-mono/packages/taiko-client/internal/utils"
	"github.com/taikoxyz/taiko-mono/packages/taiko-client/pkg/config"
	"github.com/taikoxyz/taiko-mono/packages/taiko-client/pkg/rpc"
	builder "github.com/taikoxyz/taiko-mono/packages/taiko-client/proposer/transaction_builder"
)

// Proposer keep proposing new transactions from L2 execution engine's tx pool at a fixed interval.
type Proposer struct {
	// configurations
	*Config

	// RPC clients
	rpc *rpc.Client

	// Private keys and account addresses
	proposerAddress common.Address

	// proposingTimer *time.Timer

	// Transaction builder
	txBuilder builder.ProposeBlockTransactionBuilder

	// Protocol configurations
	protocolConfigs *bindings.TaikoDataConfig

	chainConfig *config.ChainConfig

	lastProposedAt time.Time
	totalEpochs    uint64

	txmgrSelector *utils.TxMgrSelector

	ctx context.Context
	wg  sync.WaitGroup
}

// InitFromCli initializes the given proposer instance based on the command line flags.
func (p *Proposer) InitFromCli(ctx context.Context, c *cli.Context) error {
	cfg, err := NewConfigFromCliContext(c)
	if err != nil {
		return err
	}

	return p.InitFromConfig(ctx, cfg, nil, nil)
}

// InitFromConfig initializes the proposer instance based on the given configurations.
func (p *Proposer) InitFromConfig(
	ctx context.Context, cfg *Config,
	txMgr *txmgr.SimpleTxManager,
	privateTxMgr *txmgr.SimpleTxManager,
) (err error) {
	p.proposerAddress = crypto.PubkeyToAddress(cfg.L1ProposerPrivKey.PublicKey)
	p.ctx = ctx
	p.Config = cfg
	p.lastProposedAt = time.Now()

	// RPC clients
	if p.rpc, err = rpc.NewClient(p.ctx, cfg.ClientConfig); err != nil {
		return fmt.Errorf("initialize rpc clients error: %w", err)
	}

	// Protocol configs
	p.protocolConfigs = encoding.GetProtocolConfig(p.rpc.L2.ChainID.Uint64())

	log.Info("Protocol configs", "configs", p.protocolConfigs)

	if txMgr == nil {
		if txMgr, err = txmgr.NewSimpleTxManager(
			"proposer",
			log.Root(),
			&metrics.TxMgrMetrics,
			*cfg.TxmgrConfigs,
		); err != nil {
			return err
		}
	}

	if privateTxMgr == nil && cfg.PrivateTxmgrConfigs != nil && len(cfg.PrivateTxmgrConfigs.L1RPCURL) > 0 {
		if privateTxMgr, err = txmgr.NewSimpleTxManager(
			"privateMempoolProposer",
			log.Root(),
			&metrics.TxMgrMetrics,
			*cfg.PrivateTxmgrConfigs,
		); err != nil {
			return err
		}
	}

	p.txmgrSelector = utils.NewTxMgrSelector(txMgr, privateTxMgr, nil)

	chainConfig := config.NewChainConfig(p.protocolConfigs)
	p.chainConfig = chainConfig

	if cfg.BlobAllowed {
		p.txBuilder = builder.NewBlobTransactionBuilder(
			p.rpc,
			p.L1ProposerPrivKey,
			cfg.TaikoL1Address,
			cfg.ProverSetAddress,
			cfg.L2SuggestedFeeRecipient,
			cfg.ProposeBlockTxGasLimit,
			cfg.ExtraData,
			chainConfig,
		)
	} else {
		p.txBuilder = builder.NewCalldataTransactionBuilder(
			p.rpc,
			p.L1ProposerPrivKey,
			cfg.L2SuggestedFeeRecipient,
			cfg.TaikoL1Address,
			cfg.ProverSetAddress,
			cfg.ProposeBlockTxGasLimit,
			cfg.ExtraData,
			chainConfig,
		)
	}

	return nil
}

// Start starts the proposer's main loop.
func (p *Proposer) Start() error {
	startRPCServer(p)

	// p.wg.Add(1)
	// go p.eventLoop()
	return nil
}

// eventLoop starts the main loop of Taiko proposer.
// func (p *Proposer) eventLoop() {
// 	defer func() {
// 		p.proposingTimer.Stop()
// 		p.wg.Done()
// 	}()

// 	for {
// 		p.updateProposingTicker()

// 		select {
// 		case <-p.ctx.Done():
// 			return
// 		// proposing interval timer has been reached
// 		case <-p.proposingTimer.C:
// 			metrics.ProposerProposeEpochCounter.Add(1)
// 			p.totalEpochs++

// 			// Attempt a proposing operation
// 			if err := p.ProposeOp(p.ctx); err != nil {
// 				log.Error("Proposing operation error", "error", err)
// 				continue
// 			}
// 		}
// 	}
// }

// Args represents the arguments to be passed to the RPC method.
type Args struct {
}

type RPCReplyL2TxLists struct {
	TxLists        []types.Transactions
	TxListBytes    [][]byte
	ParentMetaHash common.Hash
	ParentBlockID  uint64
}

type CustomResponse struct {
	Result *RPCReplyL2TxLists `json:"result,omitempty"`
	Error  interface{}        `json:"error,omitempty"`
}

// RPC is the receiver type for the RPC methods.
type RPC struct {
	proposer *Proposer
}

func (p *RPC) GetL2TxLists(_ *http.Request, _ *Args, reply *RPCReplyL2TxLists) error {
	txLists, compressedTxLists, err := p.proposer.ProposeOpForTakingL2Blocks(context.Background())
	if err != nil {
		return err
	}
	log.Info("Received L2 txLists ", "txListsLength", len(txLists))
	if len(txLists) == 1 {
		log.Info("Single L2 txList", "txList", txLists[0])
	}

	forkHeight := new(big.Int).SetUint64(p.proposer.chainConfig.ProtocolConfigs.OntakeForkHeight)
	parent, err := p.proposer.getParentOfLatestProposedBlock(p.proposer.ctx, p.proposer.rpc, forkHeight)
	if err != nil {
		return err
	}

	*reply = RPCReplyL2TxLists{TxLists: txLists, TxListBytes: compressedTxLists, ParentMetaHash: parent.MetaHash, ParentBlockID: parent.BlockId}
	return nil
}

const rpcPort = 1234

func startRPCServer(proposer *Proposer) {
	s := gorilla_rcp.NewServer()
	s.RegisterCodec(NewCustomCodec(), "application/json")
	proposerRPC := &RPC{proposer: proposer}
	err := s.RegisterService(proposerRPC, "")
	if err != nil {
		log.Error("Failed to register proposer RPC service", "error", err)
	}

	http.Handle("/rpc", s)
	log.Info("Starting JSON-RPC server", "port", rpcPort)

	// Create a custom HTTP server with timeouts
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", rpcPort),
		Handler:      s,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Error("Failed to start HTTP server", "error", err)
		}
	}()
}

type CustomCodec struct {
	*json2.Codec
}

func NewCustomCodec() *CustomCodec {
	return &CustomCodec{json2.NewCodec()}
}

func (c *CustomCodec) WriteResponse(w http.ResponseWriter, reply interface{}, methodErr error) error {
	response := CustomResponse{}

	if methodErr != nil {
		response.Error = methodErr.Error()
	} else if reply != nil {
		response.Result = reply.(*RPCReplyL2TxLists)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(w)
	return encoder.Encode(response)
}

// Close closes the proposer instance.
func (p *Proposer) Close(_ context.Context) {
	p.wg.Wait()
}

// fetchPoolContent fetches the transaction pool content from L2 execution engine.
func (p *Proposer) fetchPoolContent(filterPoolContent bool) ([]types.Transactions, error) {
	var (
		minTip  = p.MinTip
		startAt = time.Now()
	)
	// If `--epoch.allowZeroInterval` flag is set, allow proposing zero tip transactions once when
	// the total epochs number is divisible by the flag value.
	if p.AllowZeroInterval > 0 && p.totalEpochs%p.AllowZeroInterval == 0 {
		minTip = 0
	}

	// Fetch the pool content.
	preBuiltTxList, err := p.rpc.GetPoolContent(
		p.ctx,
		p.proposerAddress,
		p.protocolConfigs.BlockMaxGasLimit,
		rpc.BlockMaxTxListBytes,
		p.LocalAddresses,
		p.MaxProposedTxListsPerEpoch,
		minTip,
		p.chainConfig,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch transaction pool content: %w", err)
	}

	metrics.ProposerPoolContentFetchTime.Set(time.Since(startAt).Seconds())

	txLists := []types.Transactions{}
	for i, txs := range preBuiltTxList {
		// Filter the pool content if the filterPoolContent flag is set.
		if txs.EstimatedGasUsed < p.MinGasUsed && txs.BytesLength < p.MinTxListBytes && filterPoolContent {
			log.Info(
				"Pool content skipped",
				"index", i,
				"estimatedGasUsed", txs.EstimatedGasUsed,
				"minGasUsed", p.MinGasUsed,
				"bytesLength", txs.BytesLength,
				"minBytesLength", p.MinTxListBytes,
			)
			break
		}
		txLists = append(txLists, txs.TxList)
	}
	// If the pool content is empty and the checkPoolContent flag is not set, return an empty list.
	if !filterPoolContent && len(txLists) == 0 {
		log.Info(
			"Pool content is empty, proposing an empty block",
			"lastProposedAt", p.lastProposedAt,
			"minProposingInternal", p.MinProposingInternal,
		)
		txLists = append(txLists, types.Transactions{})
	}

	// If LocalAddressesOnly is set, filter the transactions by the local addresses.
	if p.LocalAddressesOnly {
		var (
			localTxsLists []types.Transactions
			signer        = types.LatestSignerForChainID(p.rpc.L2.ChainID)
		)
		for _, txs := range txLists {
			var filtered types.Transactions
			for _, tx := range txs {
				sender, err := types.Sender(signer, tx)
				if err != nil {
					return nil, err
				}

				for _, localAddress := range p.LocalAddresses {
					if sender == localAddress {
						filtered = append(filtered, tx)
					}
				}
			}

			if filtered.Len() != 0 {
				localTxsLists = append(localTxsLists, filtered)
			}
		}
		txLists = localTxsLists
	}

	log.Info("Transactions lists count", "count", len(txLists))

	return txLists, nil
}

// ProposeOp performs a proposing operation, fetching transactions
// from L2 execution engine's tx pool, splitting them by proposing constraints,
// and then proposing them to TaikoL1 contract.
func (p *Proposer) ProposeOp(ctx context.Context) error {
	// Check if it's time to propose unfiltered pool content.
	filterPoolContent := time.Now().Before(p.lastProposedAt.Add(p.MinProposingInternal))

	// Wait until L2 execution engine is synced at first.
	if err := p.rpc.WaitTillL2ExecutionEngineSynced(ctx); err != nil {
		return fmt.Errorf("failed to wait until L2 execution engine synced: %w", err)
	}

	log.Info(
		"Start fetching L2 execution engine's transaction pool content",
		"filterPoolContent", filterPoolContent,
		"lastProposedAt", p.lastProposedAt,
	)

	txLists, err := p.fetchPoolContent(filterPoolContent)
	if err != nil {
		return err
	}

	// If the pool content is empty, return.
	if len(txLists) == 0 {
		return nil
	}

	// Propose the transactions lists.
	return p.ProposeTxLists(ctx, txLists)
}

// ProposeTxList proposes the given transactions lists to TaikoL1 smart contract.
func (p *Proposer) ProposeTxLists(ctx context.Context, txLists []types.Transactions) error {
	// Check if the current L2 chain is after ontake fork.
	state, err := rpc.GetProtocolStateVariables(p.rpc.TaikoL1, &bind.CallOpts{Context: ctx})
	if err != nil {
		return err
	}

	// If the current L2 chain is before ontake fork, propose the transactions lists one by one.
	if !p.chainConfig.IsOntake(new(big.Int).SetUint64(state.B.NumBlocks)) {
		g, gCtx := errgroup.WithContext(ctx)
		for _, txs := range txLists[:utils.Min(p.MaxProposedTxListsPerEpoch, uint64(len(txLists)))] {
			nonce, err := p.rpc.L1.PendingNonceAt(ctx, p.proposerAddress)
			if err != nil {
				log.Error("Failed to get proposer nonce", "error", err)
				break
			}

			log.Info("Proposer current pending nonce", "nonce", nonce)

			g.Go(func() error {
				if err := p.ProposeTxListLegacy(gCtx, txs); err != nil {
					return err
				}
				p.lastProposedAt = time.Now()
				return nil
			})

			if err := p.rpc.WaitL1NewPendingTransaction(ctx, p.proposerAddress, nonce); err != nil {
				log.Error("Failed to wait for new pending transaction", "error", err)
			}
		}

		return g.Wait()
	}

	// If the current L2 chain is after ontake fork, batch propose all L2 transactions lists.
	if err := p.ProposeTxListOntake(ctx, txLists); err != nil {
		return err
	}
	p.lastProposedAt = time.Now()
	return nil
}

func (p *Proposer) ProposeOpForTakingL2Blocks(ctx context.Context) ([]types.Transactions, [][]byte, error) {
	log.Info("ProposeOpForTakingL2Blocks")
	// Check if it's time to propose unfiltered pool content.
	filterPoolContent := time.Now().Before(p.lastProposedAt.Add(p.MinProposingInternal))

	// Wait until L2 execution engine is synced at first.
	if err := p.rpc.WaitTillL2ExecutionEngineSynced(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to wait until L2 execution engine synced: %w", err)
	}

	log.Info(
		"Start fetching L2 execution engine's transaction pool content",
		"filterPoolContent", filterPoolContent,
		"lastProposedAt", p.lastProposedAt,
	)

	txLists, err := p.fetchPoolContent(filterPoolContent)
	if err != nil {
		return nil, nil, err
	}

	// If the pool content is empty, return.
	if len(txLists) == 0 {
		return nil, nil, nil
	}

	if len(txLists) == 1 && len(txLists[0]) == 0 {
		return []types.Transactions{}, [][]byte{}, nil
	}

	compressedTxLists := [][]byte{}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get parent meta hash: %w", err)
	}

	//TODO adjust the Max value
	for _, txs := range txLists[:utils.Min(p.MaxProposedTxListsPerEpoch, uint64(len(txLists)))] {
		txListBytes, err := rlp.EncodeToBytes(txs)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encode transactions: %w", err)
		}
		compressedTxListBytes, err := utils.Compress(txListBytes)
		if err != nil {
			return nil, nil, err
		}
		compressedTxLists = append(compressedTxLists, compressedTxListBytes)
		p.lastProposedAt = time.Now() //TODO check if it's correct
	}

	return txLists, compressedTxLists, nil
}

// ProposeTxListLegacy proposes the given transactions list to TaikoL1 smart contract.
func (p *Proposer) ProposeTxListLegacy(
	ctx context.Context,
	txList types.Transactions,
) error {
	txListBytes, err := rlp.EncodeToBytes(txList)
	if err != nil {
		return fmt.Errorf("failed to encode transactions: %w", err)
	}

	compressedTxListBytes, err := utils.Compress(txListBytes)
	if err != nil {
		return err
	}

	proverAddress := p.proposerAddress
	if p.Config.ClientConfig.ProverSetAddress != rpc.ZeroAddress {
		proverAddress = p.Config.ClientConfig.ProverSetAddress
	}

	ok, err := rpc.CheckProverBalance(
		ctx,
		p.rpc,
		proverAddress,
		p.TaikoL1Address,
		p.protocolConfigs.LivenessBond,
	)

	if err != nil {
		log.Warn("Failed to check prover balance", "error", err)
		return err
	}

	if !ok {
		return errors.New("insufficient prover balance")
	}

	txCandidate, err := p.txBuilder.BuildLegacy(
		ctx,
		p.IncludeParentMetaHash,
		compressedTxListBytes,
	)
	if err != nil {
		log.Warn("Failed to build TaikoL1.proposeBlock transaction", "error", encoding.TryParsingCustomError(err))
		return err
	}

	if err := p.sendTx(ctx, txCandidate); err != nil {
		return err
	}

	log.Info("📝 Propose transactions succeeded", "txs", len(txList))

	metrics.ProposerProposedTxListsCounter.Add(1)
	metrics.ProposerProposedTxsCounter.Add(float64(len(txList)))

	return nil
}

// ProposeTxListOntake proposes the given transactions lists to TaikoL1 smart contract.
func (p *Proposer) ProposeTxListOntake(
	ctx context.Context,
	txLists []types.Transactions,
) error {
	var (
		proverAddress     = p.proposerAddress
		txListsBytesArray [][]byte
		txNums            []int
		totalTxs          int
	)
	for _, txs := range txLists {
		txListBytes, err := rlp.EncodeToBytes(txs)
		if err != nil {
			return fmt.Errorf("failed to encode transactions: %w", err)
		}

		compressedTxListBytes, err := utils.Compress(txListBytes)
		if err != nil {
			return err
		}

		txListsBytesArray = append(txListsBytesArray, compressedTxListBytes)
		txNums = append(txNums, len(txs))
		totalTxs += len(txs)
	}

	if p.Config.ClientConfig.ProverSetAddress != rpc.ZeroAddress {
		proverAddress = p.Config.ClientConfig.ProverSetAddress
	}

	ok, err := rpc.CheckProverBalance(
		ctx,
		p.rpc,
		proverAddress,
		p.TaikoL1Address,
		new(big.Int).Mul(p.protocolConfigs.LivenessBond, new(big.Int).SetUint64(uint64(len(txLists)))),
	)

	if err != nil {
		log.Warn("Failed to check prover balance", "error", err)
		return err
	}

	if !ok {
		return errors.New("insufficient prover balance")
	}

	txCandidate, err := p.txBuilder.BuildOntake(ctx, txListsBytesArray)
	if err != nil {
		log.Warn("Failed to build TaikoL1.proposeBlocksV2 transaction", "error", encoding.TryParsingCustomError(err))
		return err
	}

	if err := p.sendTx(ctx, txCandidate); err != nil {
		return err
	}

	log.Info("📝 Batch propose transactions succeeded", "txs", txNums)

	metrics.ProposerProposedTxListsCounter.Add(float64(len(txLists)))
	metrics.ProposerProposedTxsCounter.Add(float64(totalTxs))

	return nil
}

// updateProposingTicker updates the internal proposing timer.
// func (p *Proposer) updateProposingTicker() {
// 	if p.proposingTimer != nil {
// 		p.proposingTimer.Stop()
// 	}

// 	var duration time.Duration
// 	if p.ProposeInterval != 0 {
// 		duration = p.ProposeInterval
// 	} else {
// 		// Random number between 12 - 120
// 		randomSeconds := rand.Intn(120-11) + 12 // nolint: gosec
// 		duration = time.Duration(randomSeconds) * time.Second
// 	}

// 	p.proposingTimer = time.NewTimer(duration)
// }

// sendTx is the internal function to send a transaction with a selected tx manager.
func (p *Proposer) sendTx(ctx context.Context, txCandidate *txmgr.TxCandidate) error {
	txMgr, isPrivate := p.txmgrSelector.Select()
	receipt, err := txMgr.Send(ctx, *txCandidate)
	if err != nil {
		log.Warn(
			"Failed to send TaikoL1.proposeBlock / TaikoL1.proposeBlocksV2 transaction by tx manager",
			"isPrivateMempool", isPrivate,
			"error", encoding.TryParsingCustomError(err),
		)
		if isPrivate {
			p.txmgrSelector.RecordPrivateTxMgrFailed()
		}
		return err
	}

	if receipt.Status != types.ReceiptStatusSuccessful {
		return fmt.Errorf("failed to propose block: %s", receipt.TxHash.Hex())
	}
	return nil
}

// Name returns the application name.
func (p *Proposer) Name() string {
	return "proposer"
}

// getParentOfLatestProposedBlock returns the parent block of the latest proposed block in protocol
func (p *Proposer) getParentOfLatestProposedBlock(
	ctx context.Context,
	rpc *rpc.Client,
	forkHeight *big.Int,
) (*bindings.TaikoDataBlockV2, error) {
	state, err := rpc.TaikoL1.State(&bind.CallOpts{Context: ctx})
	if err != nil {
		return nil, err
	}

	blockNum := new(big.Int).SetUint64(state.SlotB.NumBlocks - 1)
	var parent bindings.TaikoDataBlockV2
	if isBlockForked(forkHeight, blockNum) {
		parent, err = rpc.GetL2BlockInfoV2(ctx, blockNum)
	} else {
		parent, err = rpc.GetL2BlockInfo(ctx, blockNum)
	}
	if err != nil {
		return nil, err
	}

	return &parent, nil
}

// isBlockForked returns whether a fork scheduled at block s is active at the
// given head block.
func isBlockForked(s, head *big.Int) bool {
	if s == nil || head == nil {
		return false
	}
	return s.Cmp(head) <= 0
}
