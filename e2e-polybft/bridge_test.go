package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/0xPolygon/polygon-edge/command/genesis"
	"github.com/0xPolygon/polygon-edge/command/rootchain/helper"
	"github.com/0xPolygon/polygon-edge/consensus/polybft"
	"github.com/0xPolygon/polygon-edge/consensus/polybft/artifacts"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
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
	os.Setenv("EDGE_BINARY", "/Users/boris/GolandProjects/polygon-edge/polygon-edge")

	key, err := ethgow.GenerateKey()
	require.NoError(t, err)

	//scpath := "../core-contracts/artifacts/contracts/"
	//rootchainArtifact, err := polybft.ReadArtifact(scpath, "root/CheckpointManager.sol", "CheckpointManager")
	//require.NoError(t, err)
	//exitHelperArtifact, err := polybft.ReadArtifact(scpath, "root/ExitHelper.sol", "ExitHelper")
	//require.NoError(t, err)
	//L1Artifact, err := polybft.ReadArtifact(scpath, "root/L1.sol", "L1")
	//require.NoError(t, err)
	//L2StateSenderArtifact, err := polybft.ReadArtifact(scpath, "child/L2StateSender.sol", "L2StateSender")
	//require.NoError(t, err)

	input, err := artifacts.Rootchain.Abi.GetMethod("currentEpoch").Encode([]interface{}{})
	require.NoError(t, err)
	inputBN, err := artifacts.Rootchain.Abi.GetMethod("currentCheckpointBlockNumber").Encode([]interface{}{})
	require.NoError(t, err)

	cluster := framework.NewTestCluster(t, 5,
		framework.WithBridge(),
		framework.WithPremine(types.Address(key.Address())),
	)
	defer cluster.Stop()

	// wait for a couple of blocks
	require.NoError(t, cluster.WaitForBlock(2, 2*time.Minute))

	validators, err := genesis.ReadValidatorsByRegexp(cluster.Config.TmpDir, cluster.Config.ValidatorPrefix)
	require.NoError(t, err)

	rootchainClient, err := jsonrpc.NewClient(txrelayer.DefaultRPCAddress)
	require.NoError(t, err)

	txRelayer, err := txrelayer.NewTxRelayer(txrelayer.WithIPAddress(txrelayer.DefaultRPCAddress))
	l2Relayer, err := txrelayer.NewTxRelayer(txrelayer.WithIPAddress(cluster.Servers[0].JSONRPCAddr()))
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

	receipt, err := txRelayer.SendTransaction(&ethgo.Transaction{
		To:    nil, // contract deployment
		Input: artifacts.L1Exit.Bytecode,
	}, helper.GetRootchainAdminKey())
	require.NoError(t, err)
	l1ContractAddress := receipt.ContractAddress
	t.Log("l1 deploy", l1ContractAddress, receipt.Status)

	tx := &ethgo.Transaction{
		From:  ethgo.Address(validators[0].Address),
		Input: artifacts.L2StateSender.Bytecode,
	}
	receipt, err = l2Relayer.SendTransaction(tx, key)
	require.NoError(t, err)
	l2StateSenderAddress := receipt.ContractAddress
	t.Log(l2StateSenderAddress, receipt.Status)

	stateSenderData := []byte{123}
	//syncState(address receiver, bytes calldata data) external
	stateSenderInput, err := artifacts.L2StateSender.Abi.GetMethod("syncState").Encode([]interface{}{
		l1ContractAddress,
		stateSenderData,
	})
	require.NoError(t, err)
	receipt, err = l2Relayer.SendTransaction(&ethgo.Transaction{
		To:    &l2StateSenderAddress,
		Input: stateSenderInput,
	}, key)
	require.NoError(t, err)
	t.Log(receipt.Status, receipt.BlockNumber)
	l2SenderBlock := receipt.BlockNumber

	receipt, err = l2Relayer.SendTransaction(&ethgo.Transaction{
		To:    &l2StateSenderAddress,
		Input: stateSenderInput,
	}, key)
	require.NoError(t, err)
	t.Log(receipt.Status, receipt.BlockNumber)

	receipt, err = txRelayer.SendTransaction(&ethgo.Transaction{
		To:    nil, // contract deployment
		Input: artifacts.ExitHelper.Bytecode,
	}, helper.GetRootchainAdminKey())
	require.NoError(t, err)
	exitHelperContractAddress := ethgo.Address(receipt.ContractAddress)
	t.Log("exitHelperContractAddress deploy", exitHelperContractAddress, receipt.Status)

	exitHelperInit, err := artifacts.ExitHelper.Abi.GetMethod("initialize").Encode([]interface{}{helper.CheckpointManagerAddress})
	require.NoError(t, err)
	receipt, err = txRelayer.SendTransaction(&ethgo.Transaction{
		To:    &exitHelperContractAddress, // contract deployment
		Input: exitHelperInit,
	}, helper.GetRootchainAdminKey())
	require.NoError(t, err)

	checkpointManagerAddress := ethgo.Address(helper.CheckpointManagerAddress)
	for {
		t.Log(rootchainClient.Eth().Call(&ethgo.CallMsg{
			From: helper.GetRootchainAdminKey().Address(),
			To:   &checkpointManagerAddress,
			Data: input,
		}, ethgo.Latest))
		t.Log(rootchainClient.Eth().Call(&ethgo.CallMsg{
			From: helper.GetRootchainAdminKey().Address(),
			To:   &checkpointManagerAddress,
			Data: inputBN,
		}, ethgo.Latest))

		blockNumber, err := cluster.Servers[0].JSONRPC().Eth().BlockNumber()
		require.NoError(t, err)
		t.Log(blockNumber)

		getLatestCheckpointBlockInput, err := artifacts.Rootchain.Abi.GetMethod("currentCheckpointBlockNumber").Encode([]interface{}{})
		require.NoError(t, err)
		v, err := txRelayer.Call(ethgo.Address(helper.GetRootchainAdminAddr()), ethgo.Address(helper.CheckpointManagerAddress), getLatestCheckpointBlockInput)
		t.Log("getLatestCheckpoint", v, err)

		getCheckpoint := func(i int64) string {
			getCheckpoint, err := artifacts.Rootchain.Abi.GetMethod("checkpoints").Encode([]interface{}{big.NewInt(i)})
			require.NoError(t, err)
			v, err := txRelayer.Call(ethgo.Address(helper.GetRootchainAdminAddr()), ethgo.Address(helper.CheckpointManagerAddress), getCheckpoint)
			require.NoError(t, err)
			/*        uint256 epoch;
			uint256 blockNumber;
			bytes32 eventRoot;
			*/
			checkpointABIType := abi.MustNewType("tuple(uint256 epoch, uint256 blockNumber, bytes32 eventRoot)")
			dc, err := checkpointABIType.Decode([]byte(v))
			require.NoError(t, err)
			t.Log(dc)
			return v
		}

		t.Log("blockNumber", blockNumber)
		t.Log("getLatestCheckpoint 1", getCheckpoint(1))
		t.Log("getLatestCheckpoint 2", getCheckpoint(2))
		t.Log("getLatestCheckpoint 3", getCheckpoint(3))

		if blockNumber > 25 {
			/*
				curl -X POST --data '{"jsonrpc":"2.0","method":"bridge_generateExitProof",
				"params":["0x001", "0x001", "0x0010"],"id":1}'
				// Result
				{
					"id":1,
					"jsonrpc": "2.0",
					"result":"[\"0x000000000000000000000000000000000000000000000102030405060708090a\"]"
				}
			*/
			//query := struct {
			//	Jsonrpc string   `json:"jsonrpc"`
			//	Method  string   `json:"method"`
			//	Params  []string `json:"params"`
			//	Id      int      `json:"id"`
			//}{
			//	"2.0",
			//	"bridge_generateExitProof",
			//	[]string{"0x001", fmt.Sprintf("0x%x", 2), fmt.Sprintf("0x%x", l2SenderBlock)},
			//	1,
			//}
			//_ = l2SenderBlock
			//d, err := json.Marshal(query)
			//require.NoError(t, err)
			//resp, err := http.Post(cluster.Servers[0].JSONRPCAddr(), "application/json", bytes.NewReader(d))
			//require.NoError(t, err)
			//s, err := io.ReadAll(resp.Body)
			//require.NoError(t, err)
			//t.Log("resp:", string(s))
			//
			//rspProof := struct {
			//	Result []string `json:"result"`
			//}{
			//	Result: nil,
			//}
			//json.Unmarshal(s, &rspProof)
			//
			//proof := make([]types.Hash, len(rspProof.Result))
			//for i, v := range rspProof.Result {
			//	proof[i] = types.StringToHash(v)
			//}
			proof, err := getExitProof(cluster.Servers[0].JSONRPCAddr(), 1, 2, l2SenderBlock)
			require.NoError(t, err)
			/*
				blockNumber,
				leafIndex,
				proofExitEvent,
				proof,

			*/

			proofExitEventEncoded, err := polybft.ExitEventABIType.Encode(&polybft.ExitEvent{
				ID:       1,
				Sender:   key.Address(),
				Receiver: l1ContractAddress,
				Data:     stateSenderData,
				//fixme shouldnt be there
				EpochNumber: 2,
				BlockNumber: l2SenderBlock,
			})
			require.NoError(t, err)
			fmt.Println(proofExitEventEncoded)
			exitInput, err := artifacts.ExitHelper.Abi.GetMethod("exit").Encode([]interface{}{
				big.NewInt(20),
				//fixme not obvious how to get it
				big.NewInt(0),
				proofExitEventEncoded,
				proof,
			})
			require.NoError(t, err)
			exitResp, err := txRelayer.SendTransaction(&ethgo.Transaction{
				To:    &exitHelperContractAddress,
				Input: exitInput,
			}, helper.GetRootchainAdminKey())
			require.NoError(t, err)
			t.Log("exitResp", exitResp)

			getProcessed, err := artifacts.ExitHelper.Abi.GetMethod("processedExits").Encode([]interface{}{big.NewInt(1)})
			require.NoError(t, err)
			res, err := txRelayer.Call(ethgo.Address(helper.GetRootchainAdminAddr()), exitHelperContractAddress, getProcessed)
			require.NoError(t, err)
			respBytes, err := types.ParseBytes(&res)
			require.Equal(t, respBytes[len(respBytes)-1], uint8(1))
			return
		}

		time.Sleep(time.Second)
	}

}

/*
exitID, epoch, checkpointBlock uint64
curl -X POST --data '{"jsonrpc":"2.0","method":"bridge_generateExitProof",
"params":["0x001", "0x001", "0x0010"],"id":1}'
// Result

	{
		"id":1,
		"jsonrpc": "2.0",
		"result":"[\"0x000000000000000000000000000000000000000000000102030405060708090a\"]"
	}
*/
func getExitProof(rpcAddress string, exitID, epoch, checkpointBlock uint64) ([]types.Hash, error) {

	query := struct {
		Jsonrpc string   `json:"jsonrpc"`
		Method  string   `json:"method"`
		Params  []string `json:"params"`
		Id      int      `json:"id"`
	}{
		"2.0",
		"bridge_generateExitProof",
		[]string{fmt.Sprintf("0x%x", exitID), fmt.Sprintf("0x%x", epoch), fmt.Sprintf("0x%x", checkpointBlock)},
		1,
	}
	d, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(rpcAddress, "application/json", bytes.NewReader(d))
	if err != nil {
		return nil, err
	}

	s, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	fmt.Println("proof resp:", string(s))

	rspProof := struct {
		Result []string `json:"result"`
	}{
		Result: nil,
	}
	err = json.Unmarshal(s, &rspProof)
	if err != nil {
		return nil, err
	}

	proof := make([]types.Hash, len(rspProof.Result))
	for i, v := range rspProof.Result {
		proof[i] = types.StringToHash(v)
	}
	return proof, nil
}

func ABICall(relayer txrelayer.TxRelayer, artifact *polybft.Artifact, address ethgo.Address, method string, params ...interface{}) (string, error) {
	getProcessed, err := artifact.Abi.GetMethod(method).Encode(params)
	if err != nil {
		return "", err
	}
	return relayer.Call(ethgo.Address(helper.GetRootchainAdminAddr()), address, getProcessed)
}
