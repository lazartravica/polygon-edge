package polybft

import (
	"errors"
	"github.com/0xPolygon/polygon-edge/chain"
	"github.com/0xPolygon/polygon-edge/contracts"
	"github.com/0xPolygon/polygon-edge/helper/hex"
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
	c := &checkpointManager{
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

	c := &checkpointManager{
		blockchain:       &blockchainMock{},
		consensusBackend: backendMock,
		logger:           hclog.NewNullLogger(),
	}
	checkpointDataEncoded, err := c.abiEncodeCheckpointBlock(header.Number, header.Hash, *extra, nextValidators.getPublicIdentities())
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

			checkpointMgr := &checkpointManager{
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

func TestSubmitCheckpoint(t *testing.T) {
	t.Parallel()

	scpath := "../../core-contracts/artifacts/contracts/"
	rootchainArtifact, err := ReadArtifact(scpath, "root/CheckpointManager.sol", "CheckpointManager")
	if err != nil {
		t.Fatal(err)
	}
	blsArtifact, err := ReadArtifact(scpath, "common/BLS.sol", "BLS")
	if err != nil {
		t.Fatal(err)
	}

	currentValidators := newTestValidatorsWithAliases([]string{"A", "B", "C", "D"}, []uint64{100, 100, 100, 100})
	accSet := currentValidators.getPublicIdentities()

	senderAddress := types.Address{1}
	bn256Addr := types.Address{2}
	transition := newTestTransition(t, map[types.Address]*chain.GenesisAccount{
		senderAddress: &chain.GenesisAccount{
			Balance: big.NewInt(100000000000),
		},
		contracts.BLSContract: &chain.GenesisAccount{
			Code: blsArtifact.DeployedBytecode,
		},
		bn256Addr: &chain.GenesisAccount{
			Balance: big.NewInt(0),
			Code:    []byte("0x608060405234801561001057600080fd5b506004361061007d5760003560e01c80639b0c399a1161005b5780639b0c399a146100f7578063ad50f9c11461011e578063cbe96a5014610145578063defbcdee1461017857600080fd5b80635120675214610082578063779d890d146100bc578063783bde80146100d0575b600080fd5b6100a97f1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d81565b6040519081526020015b60405180910390f35b600080516020610db88339815191526100a9565b6100a97f198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c281565b6100a97f1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed81565b6100a97f275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec81565b610158610153366004610c9c565b61018b565b6040805194855260208501939093529183015260608201526080016100b3565b610158610186366004610cf1565b61032a565b60008080808b15801561019c57508a155b80156101a6575089155b80156101b0575088155b1561021a57871580156101c1575086155b80156101cb575085155b80156101d5575084155b61020a576101e5888888886103c1565b61020a5760405162461bcd60e51b815260040161020190610d2c565b60405180910390fd5b508692508591508490508361031b565b87158015610226575086155b8015610230575085155b801561023a575084155b156102775761024b8c8c8c8c6103c1565b6102675760405162461bcd60e51b815260040161020190610d2c565b508a92508991508890508761031b565b6102838c8c8c8c6103c1565b61029f5760405162461bcd60e51b815260040161020190610d2c565b6102ab888888886103c1565b6102c75760405162461bcd60e51b815260040161020190610d2c565b60006102e18d8d8d8d600160008f8f8f8f60016000610476565b90506103118160005b602090810291909101519083015160408401516060850151608086015160a0870151610701565b9450945094509450505b98509850985098945050505050565b600080808060018815801561033d575087155b8015610347575086155b8015610351575085155b15610365575060019750879550600061038d565b610371898989896103c1565b61038d5760405162461bcd60e51b815260040161020190610d2c565b600061039f8b8b8b8b8b87600061076c565b90506103ac8160006102ea565b929e919d509b50909950975050505050505050565b60008060008060006103d5878789896107ef565b90945092506103e6898981816107ef565b90925090506103f782828b8b6107ef565b909250905061040884848484610860565b909450925061045884847f2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e57e9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2610860565b909450925083158015610469575082155b9998505050505050505050565b61047e610c60565b8815801561048a575087155b156104cc578686868686868660005b60a089019290925260808801929092526060870192909252604086019290925260208581019390935290910201526106f1565b821580156104d8575081155b156104eb578c8c8c8c8c8c866000610499565b6104f785858b8b6107ef565b90955093506105088b8b85856107ef565b6060830152604082015261051e87878b8b6107ef565b909750955061052f8d8d85856107ef565b60a0830152608082018190528714801561054c575060a081015186145b15610591576040810151851480156105675750606081015184145b156105825761057a8d8d8d8d8d8d6108a2565b866000610499565b60016000818180808681610499565b61059d898985856107ef565b90935091506105bd858583600260200201518460035b6020020151610860565b909d509b506105d887878360045b60200201518460056105b3565b909b5099506105e98b8b81816107ef565b909950975061060a89898360045b60200201518460055b60200201516107ef565b909550935061061b89898d8d6107ef565b909950975061062c898985856107ef565b60a083015260808201526106428d8d81816107ef565b9097509550610653878785856107ef565b909750955061066487878b8b610860565b909750955061067585856002610aea565b909350915061068687878585610860565b90975095506106978b8b89896107ef565b602083015281526106aa85858989610860565b909b5099506106bb8d8d8d8d6107ef565b909b5099506106d589898360026020020151846003610600565b909d509b506106e68b8b8f8f610860565b606083015260408201525b9c9b505050505050505050505050565b600080600080600080610712610c7e565b61071c8989610b1d565b909350915061072d8d8d85856107ef565b602083015281526107408b8b85856107ef565b60608301819052604083018290528251602090930151929f929e50909c509a5098505050505050505050565b610774610c60565b87156107e45760018816156107b5578051602082015160408301516060840151608085015160a08601516107b29594939291908d8d8d8d8d8d610476565b90505b6107c38787878787876108a2565b949b509299509097509550935091506107dd600289610d6e565b9750610774565b979650505050505050565b60008061082d600080516020610db8833981519152858809600080516020610db8833981519152858809600080516020610db8833981519152610ba8565b600080516020610db883398151915280868809600080516020610db8833981519152868a09089150915094509492505050565b60008061087c8685600080516020610db8833981519152610ba8565b6108958685600080516020610db8833981519152610ba8565b9150915094509492505050565b6000806000806000806108b3610c60565b6108bf8d8d6003610aea565b602083018190528183526108d591908f8f6107ef565b602083015281526108e88b8b8b8b6107ef565b90995097506108f98d8d8d8d6107ef565b606083015260408201819052610919908260035b60200201518b8b6107ef565b60608301526040820152805161093c908260015b60200201518351846001610600565b6040830151919e509c5061095a908260035b60200201516008610aea565b60a083015260808201526109718d8d8360046105cb565b909d509b50610982898981816107ef565b60a08301526080820152604081015160608201516109a291906004610aea565b60608301819052604083018290526109bc91908f8f610860565b6060830152604082018190526109d49082600361092d565b606083015260408201526109ea8b8b6008610aea565b60208301819052818352610a0091908d8d6107ef565b60208301819052818352610a1791908360046105f7565b602083015280825260408201516060830151610a35928460016105b3565b60608301526040820152610a4b8d8d6002610aea565b6020830152808252610a5f9082600161090d565b60208301528152610a7389898360046105f7565b60a083015260808201819052610a8b9082600561094e565b826004602002018360056020020191909152528060006020020151816001602002015182600260200201518360036020020151846004602002015185600560200201519650965096509650965096505096509650965096509650969050565b600080600080516020610db8833981519152838609600080516020610db883398151915284860991509150935093915050565b60008080610b5e600080516020610db883398151915280878809600080516020610db883398151915287880908600080516020610db8833981519152610bcc565b9050600080516020610db8833981519152818609600080516020610db8833981519152828609610b9c90600080516020610db8833981519152610d90565b92509250509250929050565b60008180610bb857610bb8610d58565b610bc28484610d90565b8508949350505050565b60008060405160208152602080820152602060408201528460608201526002840360808201528360a082015260208160c08360056107d05a03fa90519250905080610c595760405162461bcd60e51b815260206004820152601a60248201527f6572726f722077697468206d6f64756c617220696e76657273650000000000006044820152606401610201565b5092915050565b6040518060c001604052806006906020820280368337509192915050565b60405180608001604052806004906020820280368337509192915050565b600080600080600080600080610100898b031215610cb957600080fd5b505086359860208801359850604088013597606081013597506080810135965060a0810135955060c0810135945060e0013592509050565b600080600080600060a08688031215610d0957600080fd5b505083359560208501359550604085013594606081013594506080013592509050565b602080825260129082015271706f696e74206e6f7420696e20637572766560701b604082015260600190565b634e487b7160e01b600052601260045260246000fd5b600082610d8b57634e487b7160e01b600052601260045260246000fd5b500490565b81810381811115610db157634e487b7160e01b600052601160045260246000fd5b9291505056fe30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47a2646970667358221220e11cec547814ba5f6de4709d5d9d4cc333d30a8791d28c5ad702058c9ff9177c64736f6c63430008110033"),
		},
	})

	// deploy a contract
	result := transition.Create2(types.Address{123}, rootchainArtifact.Bytecode, big.NewInt(0), 1000000000)
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
	result = transition.Call2(senderAddress, rcAddress, init, big.NewInt(0), 1000000000)
	require.True(t, result.Succeeded())
	require.False(t, result.Failed())
	require.NoError(t, result.Err)

	getDomain, err := rootchainArtifact.Abi.GetMethod("domain").Encode([]interface{}{})
	require.NoError(t, err)
	result = transition.Call2(senderAddress, rcAddress, getDomain, big.NewInt(0), 1000000000)
	require.Equal(t, result.ReturnValue, bls.GetDomain())

	currentCheckpointBlockNumber, err := rootchainArtifact.Abi.GetMethod("currentCheckpointBlockNumber").Encode([]interface{}{})
	require.NoError(t, err)
	result = transition.Call2(senderAddress, rcAddress, currentCheckpointBlockNumber, big.NewInt(0), 1000000000)
	t.Log("currentCheckpointBlockNumber", result.ReturnValue)

	cm := checkpointManager{
		blockchain: &blockchainMock{},
	}
	accSetHash, err := accSet.Hash()
	require.NoError(t, err)

	eventRoot := types.Hash{123}
	blockHash := types.Hash{5}
	blockNumber := uint64(1)
	epochNumber := uint64(1)
	blockRound := uint64(1)

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

	submitCheckpointEncoded, err := cm.abiEncodeCheckpointBlock(
		blockNumber,
		blockHash,
		extra,
		accSet)
	require.NoError(t, err)

	result = transition.Call2(senderAddress, rcAddress, submitCheckpointEncoded, big.NewInt(0), 1000000000)
	require.NoError(t, result.Err)
	require.True(t, result.Succeeded())
	require.False(t, result.Failed())

	result = transition.Call2(senderAddress, rcAddress, currentCheckpointBlockNumber, big.NewInt(0), 1000000000)
	t.Log("currentCheckpointBlockNumber", result.ReturnValue)

}

func L2(t *testing.T) {
	cc := &testutil.Contract{}
	cc.AddCallback(func() string {
		return `
	
		struct Validator {
			uint256[4] id;
			uint256 stake;
			uint256 totalStake;
			uint256 data;
		}
	
		function getCurrentValidatorSet() public returns (address[] memory) {
			address[] memory addresses = new address[](1);
			addresses[0] = address(1);
			return addresses;
		}
	
		function getValidator(address) public returns (Validator memory){
			uint[4] memory key = [
				1708568697487735112380375954529256823287318886168633341382922712646533763844,
				14713639476280042449606484361428781226013866637570951139712205035697871856089,
				16798350082249088544573448433070681576641749462807627179536437108134609634615,
				21427200503135995176566340351867145775962083994845221446131416289459495591422
			];
			return Validator(key, 10, 0, 0);
		}
	
		`
	})

	solcContract, err := cc.Compile()
	assert.NoError(t, err)

	bin, err := hex.DecodeString(solcContract.Bin)
	assert.NoError(t, err)

	t.Log(len(bin))
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
