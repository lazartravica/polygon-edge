package polybft

import (
	"errors"
	"github.com/0xPolygon/polygon-edge/chain"
	"github.com/0xPolygon/polygon-edge/contracts"
	"github.com/0xPolygon/polygon-edge/helper/hex"
	"github.com/0xPolygon/polygon-edge/state"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/umbracle/ethgo"
	"github.com/umbracle/ethgo/testutil"
	"math/big"
	"strconv"
	"testing"

	"github.com/0xPolygon/polygon-edge/consensus/ibft/signer"
	"github.com/0xPolygon/polygon-edge/consensus/polybft/bitmap"
	bls "github.com/0xPolygon/polygon-edge/consensus/polybft/signer"
	"github.com/0xPolygon/polygon-edge/consensus/polybft/wallet"
	"github.com/0xPolygon/polygon-edge/txrelayer"
	"github.com/0xPolygon/polygon-edge/types"
)

func TestCheckpointManager_submitCheckpoint(t *testing.T) {
	t.Parallel()

	const (
		blocksCount = 10
		epochSize   = 2
	)

	validators := newTestValidatorsWithAliases([]string{"A", "B", "C", "D", "E"})
	validatorsMetadata := validators.getPublicIdentities()
	txRelayerMock := newDummyTxRelayer(t)
	txRelayerMock.On("Call", mock.Anything, mock.Anything, mock.Anything).
		Return("2", error(nil)).
		Once()
	txRelayerMock.On("SendTransaction", mock.Anything, mock.Anything).
		Return(&ethgo.Receipt{Status: uint64(types.ReceiptSuccess)}, error(nil)).
		Times(4) // send transactions for checkpoint blocks: 4, 6, 8 (pending checkpoint blocks) and 10 (latest checkpoint block)

	backendMock := new(polybftBackendMock)
	backendMock.On("GetValidators", mock.Anything, mock.Anything).Return(validatorsMetadata)

	var (
		headersMap  = &testHeadersMap{}
		epochNumber = uint64(1)
		header      *types.Header
	)

	for i := uint64(1); i <= blocksCount; i++ {
		if i%epochSize == 1 {
			// epoch-beginning block
			checkpoint := &CheckpointData{
				BlockRound:  0,
				EpochNumber: epochNumber,
				EventRoot:   types.BytesToHash(generateRandomBytes(t)),
			}
			extra := createTestExtraObject(validatorsMetadata, validatorsMetadata, 3, 3, 3)
			extra.Checkpoint = checkpoint
			header = &types.Header{
				ExtraData: append(make([]byte, ExtraVanity), extra.MarshalRLPTo(nil)...),
			}
			epochNumber++
		} else {
			header = header.Copy()
		}

		header.Number = i
		header.ComputeHash()
		headersMap.addHeader(header)
	}

	// mock blockchain
	blockchainMock := new(blockchainMock)
	blockchainMock.On("GetHeaderByNumber", mock.Anything).Return(headersMap.getHeader)

	validatorAcc := validators.getValidator("A")
	c := &CheckpointManager{
		ChainID:          blockchainMock.GetChainID(),
		key:              wallet.NewEcdsaSigner(validatorAcc.Key()),
		txRelayer:        txRelayerMock,
		consensusBackend: backendMock,
		blockchain:       blockchainMock,
		logger:           hclog.NewNullLogger(),
	}

	err := c.submitCheckpoint(*headersMap.getHeader(blocksCount), false)
	require.NoError(t, err)
	txRelayerMock.AssertExpectations(t)

	// make sure that expected blocks are checkpointed (epoch-ending ones)
	for _, checkpointBlock := range txRelayerMock.checkpointBlocks {
		header := headersMap.getHeader(checkpointBlock)
		require.NotNil(t, header)
		require.True(t, isEndOfPeriod(header.Number, epochSize))
	}
}

func TestCheckpointManager_abiEncodeCheckpointBlock(t *testing.T) {
	t.Parallel()

	const epochSize = uint64(10)

	currentValidators := newTestValidatorsWithAliases([]string{"A", "B", "C", "D"})
	nextValidators := newTestValidatorsWithAliases([]string{"E", "F", "G", "H"})
	header := &types.Header{Number: 50}
	checkpoint := &CheckpointData{
		BlockRound:  1,
		EpochNumber: getEpochNumber(header.Number, epochSize),
		EventRoot:   types.BytesToHash(generateRandomBytes(t)),
	}

	proposalHash := generateRandomBytes(t)

	bmp := bitmap.Bitmap{}
	i := uint64(0)
	signature := &bls.Signature{}

	currentValidators.iterAcct(nil, func(v *testValidator) {
		signature = signature.Aggregate(v.mustSign(proposalHash))
		bmp.Set(i)
		i++
	})

	aggSignature, err := signature.Marshal()
	require.NoError(t, err)

	extra := &Extra{Checkpoint: checkpoint}
	extra.Committed = &Signature{
		AggregatedSignature: aggSignature,
		Bitmap:              bmp,
	}
	header.ExtraData = append(make([]byte, signer.IstanbulExtraVanity), extra.MarshalRLPTo(nil)...)
	header.ComputeHash()

	backendMock := new(polybftBackendMock)
	backendMock.On("GetValidators", mock.Anything, mock.Anything).Return(currentValidators.getPublicIdentities())

	c := &CheckpointManager{
		blockchain:       &blockchainMock{},
		consensusBackend: backendMock,
		logger:           hclog.NewNullLogger(),
	}
	checkpointDataEncoded, err := c.AbiEncodeCheckpointBlock(header.Number, header.Hash, *extra, nextValidators.getPublicIdentities())
	require.NoError(t, err)

	decodedCheckpointData, err := submitCheckpointMethod.Inputs.Decode(checkpointDataEncoded[4:])
	require.NoError(t, err)

	submitCheckpointInputData, ok := decodedCheckpointData.(map[string]interface{})
	require.True(t, ok)

	checkpointData, ok := submitCheckpointInputData["checkpoint"].(map[string]interface{})
	require.True(t, ok)

	checkpointMetadata, ok := submitCheckpointInputData["checkpointMetadata"].(map[string]interface{})
	require.True(t, ok)

	eventRoot, ok := checkpointData["eventRoot"].([types.HashLength]byte)
	require.True(t, ok)

	blockRound, ok := checkpointMetadata["blockRound"].(*big.Int)
	require.True(t, ok)

	epochNumber, ok := checkpointData["epochNumber"].(*big.Int)
	require.True(t, ok)

	blockNumber, ok := checkpointData["blockNumber"].(*big.Int)
	require.True(t, ok)

	require.Equal(t, new(big.Int).SetUint64(checkpoint.EpochNumber), epochNumber)
	require.Equal(t, new(big.Int).SetUint64(header.Number), blockNumber)
	require.Equal(t, checkpoint.EventRoot, types.BytesToHash(eventRoot[:]))
	require.Equal(t, new(big.Int).SetUint64(checkpoint.BlockRound), blockRound)
}

func TestCheckpointManager_getCurrentCheckpointID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		checkpointID string
		returnError  error
		errSubstring string
	}{
		{
			name:         "Happy path",
			checkpointID: "16",
			returnError:  error(nil),
			errSubstring: "",
		},
		{
			name:         "Rootchain call returns an error",
			checkpointID: "",
			returnError:  errors.New("internal error"),
			errSubstring: "failed to invoke currentCheckpointId function on the rootchain",
		},
		{
			name:         "Failed to parse return value from rootchain",
			checkpointID: "Hello World!",
			returnError:  error(nil),
			errSubstring: "failed to convert current checkpoint id",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			txRelayerMock := newDummyTxRelayer(t)
			txRelayerMock.On("Call", mock.Anything, mock.Anything, mock.Anything).
				Return(c.checkpointID, c.returnError).
				Once()

			checkpointMgr := &CheckpointManager{
				txRelayer: txRelayerMock,
				key:       wallet.GenerateAccount().Ecdsa,
				logger:    hclog.NewNullLogger(),
			}
			actualCheckpointID, err := checkpointMgr.getLatestCheckpointBlock()
			if c.errSubstring == "" {
				expectedCheckpointID, err := strconv.ParseUint(c.checkpointID, 0, 64)
				require.NoError(t, err)
				require.Equal(t, expectedCheckpointID, actualCheckpointID)
			} else {
				require.ErrorContains(t, err, c.errSubstring)
			}

			txRelayerMock.AssertExpectations(t)
		})
	}
}

func TestCheckpointManager_isCheckpointBlock(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		blockNumber       uint64
		checkpointsOffset uint64
		isCheckpointBlock bool
	}{
		{
			name:              "Not checkpoint block",
			blockNumber:       3,
			checkpointsOffset: 6,
			isCheckpointBlock: false,
		},
		{
			name:              "Checkpoint block",
			blockNumber:       6,
			checkpointsOffset: 6,
			isCheckpointBlock: true,
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			checkpointMgr := newCheckpointManager(wallet.NewEcdsaSigner(createTestKey(t)), c.checkpointsOffset, nil, nil, nil, hclog.NewNullLogger())
			require.Equal(t, c.isCheckpointBlock, checkpointMgr.isCheckpointBlock(c.blockNumber))
		})
	}
}

func TestPerformExit(t *testing.T) {
	t.Parallel()

	//read required contract artifacts
	scpath := "../../core-contracts/artifacts/contracts/"
	rootchainArtifact, err := ReadArtifact(scpath, "root/CheckpointManager.sol", "CheckpointManager")
	require.NoError(t, err)
	blsArtifact, err := ReadArtifact(scpath, "common/BLS.sol", "BLS")
	require.NoError(t, err)
	bls256Artifact, err := ReadArtifact(scpath, "common/BN256G2.sol", "BN256G2")
	require.NoError(t, err)
	exitHelper, err := ReadArtifact(scpath, "root/ExitHelper.sol", "ExitHelper")
	require.NoError(t, err)
	//todo move out from core contracts
	l1Art, err := ReadArtifact(scpath, "root/L1.sol", "L1")
	require.NoError(t, err)

	//create validator set
	currentValidators := newTestValidatorsWithAliases([]string{"A", "B", "C", "D"}, []uint64{100, 100, 100, 100})
	accSet := currentValidators.getPublicIdentities()

	senderAddress := types.Address{1}
	bn256Addr := types.Address{2}
	l1Cntract := types.Address{3}

	alloc := map[types.Address]*chain.GenesisAccount{
		senderAddress: &chain.GenesisAccount{
			Balance: big.NewInt(100000000000),
		},
		contracts.BLSContract: &chain.GenesisAccount{
			Code: blsArtifact.DeployedBytecode,
		},
		bn256Addr: &chain.GenesisAccount{
			Code: bls256Artifact.DeployedBytecode,
		},
		l1Cntract: &chain.GenesisAccount{
			Code: l1Art.DeployedBytecode,
		},
	}
	transition := newTestTransition(t, alloc)

	getField := func(addr types.Address, artifact *Artifact, function string, args ...interface{}) []byte {
		input, err := artifact.Abi.GetMethod(function).Encode(args)
		require.NoError(t, err)

		result := transition.Call2(senderAddress, addr, input, big.NewInt(0), 1000000000)
		require.NoError(t, result.Err)
		require.True(t, result.Succeeded())
		require.False(t, result.Failed())
		return result.ReturnValue
	}

	rootchainContractAddress := deployRootchainContract(t, transition, rootchainArtifact, senderAddress, accSet, bn256Addr)
	exitHelperContractAddress := deployExitContract(t, transition, exitHelper, senderAddress, rootchainContractAddress)

	require.Equal(t, getField(rootchainContractAddress, rootchainArtifact, "currentCheckpointBlockNumber")[31], uint8(0))

	cm := CheckpointManager{
		blockchain: &blockchainMock{},
	}
	accSetHash, err := accSet.Hash()
	require.NoError(t, err)

	blockHash := types.Hash{5}
	blockNumber := uint64(1)
	epochNumber := uint64(1)
	blockRound := uint64(1)

	exits := []*ExitEvent{
		{
			ID:       1,
			Sender:   ethgo.Address{7},
			Receiver: ethgo.Address(l1Cntract),
			Data:     []byte{123},
		},
		{
			ID:       2,
			Sender:   ethgo.Address{7},
			Receiver: ethgo.Address(l1Cntract),
			Data:     []byte{21},
		},
	}
	exitTrie, err := createExitTree(exits)
	require.NoError(t, err)

	eventRoot := exitTrie.Hash()

	checkpointData := CheckpointData{
		BlockRound:            blockRound,
		EpochNumber:           epochNumber,
		CurrentValidatorsHash: accSetHash,
		NextValidatorsHash:    accSetHash,
		EventRoot:             eventRoot,
	}

	checkpointHash, err := checkpointData.Hash(
		cm.blockchain.GetChainID(),
		blockRound,
		blockHash)
	require.NoError(t, err)

	bmp := bitmap.Bitmap{}
	i := uint64(0)
	signature := &bls.Signature{}

	currentValidators.iterAcct(nil, func(v *testValidator) {
		signature = signature.Aggregate(v.mustSign(checkpointHash[:]))
		bmp.Set(i)
		i++
	})

	aggSignature, err := signature.Marshal()
	require.NoError(t, err)

	extra := Extra{
		Checkpoint: &checkpointData,
	}
	extra.Committed = &Signature{
		AggregatedSignature: aggSignature,
		Bitmap:              bmp,
	}

	submitCheckpointEncoded, err := cm.AbiEncodeCheckpointBlock(
		blockNumber,
		blockHash,
		extra,
		accSet)
	require.NoError(t, err)

	result := transition.Call2(senderAddress, rootchainContractAddress, submitCheckpointEncoded, big.NewInt(0), 1000000000)
	require.NoError(t, result.Err)
	require.True(t, result.Succeeded())
	require.False(t, result.Failed())
	require.Equal(t, getField(rootchainContractAddress, rootchainArtifact, "currentCheckpointBlockNumber")[31], uint8(1))

	//check that the exit havent performed
	res := getField(exitHelperContractAddress, exitHelper, "processedExits", exits[0].ID)
	require.Equal(t, int(res[31]), 0)

	proofExitEvent, err := ExitEventABIType.Encode(exits[0])
	require.NoError(t, err)
	proof, err := exitTrie.GenerateProofForLeaf(proofExitEvent, 0)
	require.NoError(t, err)
	leafIndex, err := exitTrie.LeafIndex(proofExitEvent)
	require.NoError(t, err)
	t.Log("proof", proof)
	ehExit, err := exitHelper.Abi.GetMethod("exit").Encode([]interface{}{
		blockNumber,
		leafIndex,
		proofExitEvent,
		proof,
	})
	require.NoError(t, err)

	result = transition.Call2(senderAddress, exitHelperContractAddress, ehExit, big.NewInt(0), 1000000000)
	require.NoError(t, result.Err)
	require.True(t, result.Succeeded())
	require.False(t, result.Failed())

	//check true
	res = getField(exitHelperContractAddress, exitHelper, "processedExits", exits[0].ID)
	require.Equal(t, int(res[31]), 1)

	lastID := getField(l1Cntract, l1Art, "id")
	require.Equal(t, lastID[31], uint8(1))
	lastAddr := getField(l1Cntract, l1Art, "addr")
	require.Equal(t, exits[0].Sender[:], lastAddr[12:])
	lastCounter := getField(l1Cntract, l1Art, "counter")
	require.Equal(t, lastCounter[31], uint8(1))
	//todo a strange data
	//require.Equal(t, getField(l1Cntract, l1Art, "data"), exits[0].Data)
}

func deployRootchainContract(t *testing.T, transition *state.Transition, rootchainArtifact *Artifact, sender types.Address, accSet AccountSet, bn256Addr types.Address) types.Address {
	result := transition.Create2(sender, rootchainArtifact.Bytecode, big.NewInt(0), 1000000000)
	assert.NoError(t, result.Err)
	rcAddress := result.Address

	init, err := rootchainArtifact.Abi.GetMethod("initialize").Encode([4]interface{}{
		contracts.BLSContract,
		bn256Addr,
		bls.GetDomain(),
		accSet.AsGenericMaps()})
	if err != nil {
		t.Fatal(err)
	}
	result = transition.Call2(sender, rcAddress, init, big.NewInt(0), 1000000000)
	require.True(t, result.Succeeded())
	require.False(t, result.Failed())
	require.NoError(t, result.Err)

	getDomain, err := rootchainArtifact.Abi.GetMethod("domain").Encode([]interface{}{})
	require.NoError(t, err)
	result = transition.Call2(sender, rcAddress, getDomain, big.NewInt(0), 1000000000)
	require.Equal(t, result.ReturnValue, bls.GetDomain())

	return rcAddress
}

func deployExitContract(t *testing.T, transition *state.Transition, exitHelperArtifcat *Artifact, sender types.Address, rootchainContractAddress types.Address) types.Address {
	result := transition.Create2(sender, exitHelperArtifcat.Bytecode, big.NewInt(0), 1000000000)
	assert.NoError(t, result.Err)
	ehAddress := result.Address

	ehInit, err := exitHelperArtifcat.Abi.GetMethod("initialize").Encode([]interface{}{ethgo.Address(rootchainContractAddress)})
	require.NoError(t, err)

	result = transition.Call2(sender, ehAddress, ehInit, big.NewInt(0), 1000000000)
	require.NoError(t, result.Err)
	require.True(t, result.Succeeded())
	require.False(t, result.Failed())

	return ehAddress
}

func TestName1(t *testing.T) {
	L2Contract(t)
}

func L2Contract(t *testing.T) {
	cc := &testutil.Contract{}
	cc.AddCallback(func() string {
		return `
		uint256 public counter;
		uint256 public lastCommittedId;
		
		function setNextExecutionIndex(uint256 _index) public payable {
			counter = _index;
		}
		function setNextCommittedIndex(uint256 _index) public payable {
			lastCommittedId = _index;
		}`
	})

	solcContract, err := cc.Compile()
	require.NoError(t, err)

	bin, err := hex.DecodeString(solcContract.Bin)
	require.NoError(t, err)
	_ = bin
}

var _ txrelayer.TxRelayer = (*dummyTxRelayer)(nil)

type dummyTxRelayer struct {
	mock.Mock

	test             *testing.T
	checkpointBlocks []uint64
}

func newDummyTxRelayer(t *testing.T) *dummyTxRelayer {
	t.Helper()

	return &dummyTxRelayer{test: t}
}

func (d dummyTxRelayer) Call(from ethgo.Address, to ethgo.Address, input []byte) (string, error) {
	args := d.Called(from, to, input)

	return args.String(0), args.Error(1)
}

func (d *dummyTxRelayer) SendTransaction(transaction *ethgo.Transaction, key ethgo.Key) (*ethgo.Receipt, error) {
	blockNumber := getBlockNumberCheckpointSubmitInput(d.test, transaction.Input)
	d.checkpointBlocks = append(d.checkpointBlocks, blockNumber)
	args := d.Called(transaction, key)

	return args.Get(0).(*ethgo.Receipt), args.Error(1) //nolint:forcetypeassert
}

// SendTransactionLocal sends non-signed transaction (this is only for testing purposes)
func (d *dummyTxRelayer) SendTransactionLocal(txn *ethgo.Transaction) (*ethgo.Receipt, error) {
	args := d.Called(txn)

	return args.Get(0).(*ethgo.Receipt), args.Error(1) //nolint:forcetypeassert
}

func getBlockNumberCheckpointSubmitInput(t *testing.T, input []byte) uint64 {
	t.Helper()

	decoded, err := submitCheckpointMethod.Inputs.Decode(input[4:])
	require.NoError(t, err)

	submitCheckpointInputData, ok := decoded.(map[string]interface{})
	require.True(t, ok, "failed to type assert submitCheckpoint inputs")

	checkpointData, ok := submitCheckpointInputData["checkpoint"].(map[string]interface{})
	require.True(t, ok, "failed to type assert checkpoint tuple from submitCheckpoint inputs")

	blockNumber, ok := checkpointData["blockNumber"].(*big.Int)
	require.True(t, ok, "failed to extract block number from submit checkpoint inputs")

	return blockNumber.Uint64()
}
