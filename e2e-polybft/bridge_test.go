package e2e

import (
	"fmt"
	"github.com/0xPolygon/polygon-edge/command/genesis"
	"github.com/0xPolygon/polygon-edge/command/rootchain/helper"
	"github.com/0xPolygon/polygon-edge/consensus/polybft"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xPolygon/polygon-edge/contracts"
	"github.com/0xPolygon/polygon-edge/e2e-polybft/framework"
	"github.com/0xPolygon/polygon-edge/txrelayer"
	"github.com/0xPolygon/polygon-edge/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/umbracle/ethgo"
	"github.com/umbracle/ethgo/abi"
	"github.com/umbracle/ethgo/jsonrpc"
	ethgow "github.com/umbracle/ethgo/wallet"
)

var stateSyncResultEvent = abi.MustNewEvent(`event StateSyncResult(
		uint256 indexed counter,
		uint8 indexed status,
		bytes32 message)`)

type ResultEventStatus uint8

const (
	ResultEventSuccess ResultEventStatus = iota
	ResultEventFailure
)

// checkLogs is helper function which parses given ResultEvent event's logs,
// extracts status topic value and makes assertions against it.
func checkLogs(
	t *testing.T,
	logs []*ethgo.Log,
	expectedCount int,
	assertFn func(i int, status ResultEventStatus) bool,
) {
	t.Helper()
	require.Len(t, logs, expectedCount)

	for i, log := range logs {
		res, err := stateSyncResultEvent.ParseLog(log)
		assert.NoError(t, err)

		t.Logf("Block Number=%d, Decoded Log=%v", log.BlockNumber, res)

		status, ok := res["status"].(uint8)
		require.True(t, ok)

		assert.True(t, assertFn(i, ResultEventStatus(status)))
	}
}

func stateSyncEventsToAbiSlice(stateSyncEvent types.StateSyncEvent) []map[string]interface{} {
	result := make([]map[string]interface{}, 1)
	result[0] = map[string]interface{}{
		"id":       stateSyncEvent.ID,
		"sender":   stateSyncEvent.Sender,
		"receiver": stateSyncEvent.Receiver,
		"data":     stateSyncEvent.Data,
		"skip":     stateSyncEvent.Skip,
	}

	return result
}

func executeStateSync(t *testing.T, client *jsonrpc.Client, txRelayer txrelayer.TxRelayer, account ethgo.Key, stateSyncID string) {
	t.Helper()

	// retrieve state sync proof
	var stateSyncProof types.StateSyncProof
	err := client.Call("bridge_getStateSyncProof", &stateSyncProof, stateSyncID)
	require.NoError(t, err)

	t.Log("State sync proofs:", stateSyncProof)

	input, err := types.ExecuteBundleABIMethod.Encode([2]interface{}{stateSyncProof.Proof, stateSyncEventsToAbiSlice(stateSyncProof.StateSync)})
	require.NoError(t, err)

	t.Log(stateSyncEventsToAbiSlice(stateSyncProof.StateSync))

	// execute the state sync
	txn := &ethgo.Transaction{
		From:     account.Address(),
		To:       (*ethgo.Address)(&contracts.StateReceiverContract),
		GasPrice: 0,
		Gas:      types.StateTransactionGasLimit,
		Input:    input,
	}

	receipt, err := txRelayer.SendTransaction(txn, account)
	require.NoError(t, err)
	require.NotNil(t, receipt)

	t.Log("Logs", len(receipt.Logs))
}

func TestE2E_Bridge_MainWorkflow(t *testing.T) {
	const num = 10

	var (
		accounts         = make([]ethgo.Key, num)
		wallets, amounts [num]string
		premine          [num]types.Address
	)

	for i := 0; i < num; i++ {
		accounts[i], _ = ethgow.GenerateKey()
		premine[i] = types.Address(accounts[i].Address())
		wallets[i] = premine[i].String()
		amounts[i] = fmt.Sprintf("%d", 100)
	}

	cluster := framework.NewTestCluster(t, 5, framework.WithBridge(), framework.WithPremine(premine[:]...))
	defer cluster.Stop()

	// wait for a couple of blocks
	require.NoError(t, cluster.WaitForBlock(2, 1*time.Minute))

	// send a few transactions to the bridge
	require.NoError(
		t,
		cluster.EmitTransfer(
			contracts.NativeTokenContract.String(),
			strings.Join(wallets[:], ","),
			strings.Join(amounts[:], ","),
		),
	)

	// wait for a few more sprints
	require.NoError(t, cluster.WaitForBlock(30, 2*time.Minute))

	client := cluster.Servers[0].JSONRPC()
	txRelayer, err := txrelayer.NewTxRelayer(txrelayer.WithClient(client))
	require.NoError(t, err)

	// commitments should've been stored
	// execute the state sysncs
	for i := 0; i < num; i++ {
		executeStateSync(t, client, txRelayer, accounts[i], fmt.Sprintf("%x", i+1))
	}

	// the transactions are mined and there should be a success events
	id := stateSyncResultEvent.ID()
	filter := &ethgo.LogFilter{
		Topics: [][]*ethgo.Hash{
			{&id},
		},
	}

	filter.SetFromUint64(0)
	filter.SetToUint64(100)

	logs, err := cluster.Servers[0].JSONRPC().Eth().GetLogs(filter)
	require.NoError(t, err)

	// Assert that all state syncs are executed successfully
	checkLogs(t, logs, num,
		func(_ int, status ResultEventStatus) bool {
			return status == ResultEventSuccess
		})
}

func TestE2E_Bridge_L2toL1Exit(t *testing.T) {
	os.Setenv("E2E_TESTS", "true")
	os.Setenv("EDGE_BINARY", "/Users/boris/GolandProjects/polygon-edge/artifacts/polygon-edge")

	key, err := ethgow.GenerateKey()
	require.NoError(t, err)

	scpath := "../core-contracts/artifacts/contracts/"
	rootchainArtifact, err := polybft.ReadArtifact(scpath, "root/CheckpointManager.sol", "CheckpointManager")
	if err != nil {
		t.Fatal(err)
	}
	input, err := rootchainArtifact.Abi.GetMethod("currentEpoch").Encode([]interface{}{})
	require.NoError(t, err)
	inputBN, err := rootchainArtifact.Abi.GetMethod("currentCheckpointBlockNumber").Encode([]interface{}{})
	require.NoError(t, err)

	tt := time.Now()
	cluster := framework.NewTestCluster(t, 5,
		framework.WithBridge(),
		framework.WithPremine(types.Address(key.Address())),
	)
	defer cluster.Stop()

	fmt.Println("cluster created", time.Since(tt))

	// wait for a couple of blocks
	require.NoError(t, cluster.WaitForBlock(2, 2*time.Minute))
	fmt.Println("2 block", time.Since(tt))

	validators, err := genesis.ReadValidatorsByRegexp(cluster.Config.TmpDir, cluster.Config.ValidatorPrefix)
	require.NoError(t, err)
	t.Log("fund validators")

	rootchainAddr := "http://127.0.0.1:8545"
	rootchainClient, err := jsonrpc.NewClient(rootchainAddr)
	require.NoError(t, err)

	txRelayer, err := txrelayer.NewTxRelayer(txrelayer.WithIPAddress(rootchainAddr))
	require.NoError(t, err)

	for i := range validators {
		fundAddr := ethgo.Address(validators[i].Address)
		txn := &ethgo.Transaction{
			To:    &fundAddr,
			Value: big.NewInt(1000000000000000000),
		}

		receipt, err := txRelayer.SendTransactionLocal(txn)
		t.Log(receipt, err)
		if receipt != nil && receipt.Status == uint64(types.ReceiptSuccess) {
			t.Log("Funded", fundAddr)
		}
	}
	t.Log("balances")
	for _, v := range validators {
		b, err := rootchainClient.Eth().GetBalance(ethgo.Address(v.Address), ethgo.Latest)
		require.NoError(t, err)
		t.Log(v.Address, b.Uint64())
	}

	sw := sync.Once{}
	checkpointManagerAddress := ethgo.Address(helper.CheckpointManagerAddress)
	for {
		t.Log(rootchainClient.Eth().Call(&ethgo.CallMsg{
			From:     helper.GetRootchainAdminKey().Address(),
			To:       &checkpointManagerAddress,
			Data:     input,
			GasPrice: defaultGasPrice,
			Gas:      big.NewInt(defaultGasLimit),
		}, ethgo.Pending))
		t.Log(rootchainClient.Eth().Call(&ethgo.CallMsg{
			From:     helper.GetRootchainAdminKey().Address(),
			To:       &checkpointManagerAddress,
			Data:     inputBN,
			GasPrice: defaultGasPrice,
			Gas:      big.NewInt(defaultGasLimit),
		}, ethgo.Pending))
		t.Log(cluster.Servers[0].JSONRPC().Eth().BlockNumber())

		getLatestCheckpointBlockInput, err := rootchainArtifact.Abi.GetMethod("currentCheckpointBlockNumber").Encode([]interface{}{})
		require.NoError(t, err)
		v, err := txRelayer.Call(ethgo.Address(helper.GetRootchainAdminAddr()), ethgo.Address(helper.CheckpointManagerAddress), getLatestCheckpointBlockInput)
		t.Log("getLatestCheckpoint", v, err)

		if bn, _ := cluster.Servers[0].JSONRPC().Eth().BlockNumber(); bn > 30 {
			sw.Do(func() {
				t.Log("submit checkpoint")
				cmAddr := ethgo.Address(helper.CheckpointManagerAddress)
				t.Log(rootchainClient.Eth().GetCode(ethgo.Address(helper.CheckpointManagerAddress), ethgo.Latest))
				t.Log(rootchainClient.Eth().GetCode(ethgo.Address(helper.BLSAddress), ethgo.Latest))
				t.Log(rootchainClient.Eth().GetCode(ethgo.Address(helper.BN256G2Address), ethgo.Latest))
				t.Log(rootchainClient.Eth().Call(&ethgo.CallMsg{
					From: ethgo.Address(helper.GetRootchainAdminAddr()),
					To:   &cmAddr,
					Data: getLatestCheckpointBlockInput,
				}, ethgo.Latest))

				block, err := cluster.Servers[0].JSONRPC().Eth().GetBlockByNumber(10, true)
				require.NoError(t, err)

				extra, err := polybft.GetIbftExtra(block.ExtraData)
				require.NoError(t, err)
				polybft.checkp

			})
		}

		time.Sleep(time.Second)
	}

}

const (
	defaultGasPrice = 1879048192 // 0x70000000
	defaultGasLimit = 5242880    // 0x500000
)
