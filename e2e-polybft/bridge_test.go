package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/0xPolygon/polygon-edge/command/genesis"
	"github.com/0xPolygon/polygon-edge/command/rootchain/helper"
	"github.com/0xPolygon/polygon-edge/consensus/polybft"
	"github.com/0xPolygon/polygon-edge/consensus/polybft/contractsapi"
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

	cluster := framework.NewTestCluster(t, 5,
		framework.WithBridge(),
		framework.WithPremine(types.Address(key.Address())),
	)
	defer cluster.Stop()

	// wait for a couple of blocks
	require.NoError(t, cluster.WaitForBlock(2, 2*time.Minute))

	//init rpc clients
	txRelayer, err := txrelayer.NewTxRelayer(txrelayer.WithIPAddress(txrelayer.DefaultRPCAddress))
	require.NoError(t, err)
	l2Relayer, err := txrelayer.NewTxRelayer(txrelayer.WithIPAddress(cluster.Servers[0].JSONRPCAddr()))
	require.NoError(t, err)

	//add balance to validators for sending checkpoints
	validators, err := genesis.ReadValidatorsByRegexp(cluster.Config.TmpDir, cluster.Config.ValidatorPrefix)
	require.NoError(t, err)
	FundValidators(t, txRelayer, validators)

	//deploy l1,l2, ExitHelper contracts
	receipt, err := DeployTransaction(txRelayer, helper.GetRootchainAdminKey(), contractsapi.L1Exit.Bytecode)
	require.NoError(t, err)
	l1ContractAddress := receipt.ContractAddress
	receipt, err = DeployTransaction(l2Relayer, key, contractsapi.L2StateSender.Bytecode)
	require.NoError(t, err)
	l2StateSenderAddress := receipt.ContractAddress
	receipt, err = DeployTransaction(txRelayer, helper.GetRootchainAdminKey(), contractsapi.ExitHelper.Bytecode)
	require.NoError(t, err)
	exitHelperContractAddress := ethgo.Address(receipt.ContractAddress)
	receipt, err = ABITransaction(txRelayer, helper.GetRootchainAdminKey(), contractsapi.ExitHelper, exitHelperContractAddress, "initialize", helper.CheckpointManagerAddress)
	require.NoError(t, err)

	//Start test
	//send crosschain transaction on l2
	stateSenderData := []byte{123}
	receipt, err = ABITransaction(l2Relayer, key, contractsapi.L2StateSender, l2StateSenderAddress, "syncState", l1ContractAddress, stateSenderData)
	require.NoError(t, err)
	require.Equal(t, receipt.Status, uint64(types.ReceiptSuccess))

	l2SenderBlock := receipt.BlockNumber
	l2SenderBlockData, err := cluster.Servers[0].JSONRPC().Eth().GetBlockByNumber(ethgo.BlockNumber(l2SenderBlock), true)
	require.NoError(t, err)
	extra, err := polybft.GetIbftExtra(l2SenderBlockData.ExtraData)
	require.NoError(t, err)

	receipt, err = ABITransaction(l2Relayer, key, contractsapi.L2StateSender, l2StateSenderAddress, "syncState", l1ContractAddress, stateSenderData)
	require.Equal(t, receipt.Status, uint64(types.ReceiptSuccess))
	require.NoError(t, err)

	checkpointManagerAddress := ethgo.Address(helper.CheckpointManagerAddress)
	for {
		currentEpochString, err := ABICall(txRelayer, contractsapi.Rootchain, checkpointManagerAddress, "currentEpoch")
		require.NoError(t, err)
		currentEpoch, err := types.ParseUint64orHex(&currentEpochString)
		require.NoError(t, err)
		if currentEpoch >= extra.Checkpoint.EpochNumber {
			proof, err := getExitProof(cluster.Servers[0].JSONRPCAddr(), 1, extra.Checkpoint.EpochNumber, extra.Checkpoint.EpochNumber*10)
			require.NoError(t, err)

			proofExitEventEncoded, err := polybft.ExitEventABIType.Encode(&polybft.ExitEvent{
				ID:       1,
				Sender:   key.Address(),
				Receiver: l1ContractAddress,
				Data:     stateSenderData,
			})
			require.NoError(t, err)

			_, err = ABITransaction(txRelayer, helper.GetRootchainAdminKey(), contractsapi.ExitHelper, exitHelperContractAddress,
				"exit",
				big.NewInt(int64(extra.Checkpoint.EpochNumber*10)),
				//fixme not obvious how to get it
				big.NewInt(0),
				proofExitEventEncoded,
				proof,
			)
			require.NoError(t, err)

			res, err := ABICall(txRelayer, contractsapi.ExitHelper, exitHelperContractAddress, "processedExits", big.NewInt(1))
			require.NoError(t, err)
			parserRes, err := types.ParseBytes(&res)
			require.Equal(t, parserRes, uint64(1))
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

func ABICall(relayer txrelayer.TxRelayer, artifact *polybft.Artifact, contractAddress ethgo.Address, method string, params ...interface{}) (string, error) {
	input, err := artifact.Abi.GetMethod(method).Encode(params)
	if err != nil {
		return "", err
	}
	return relayer.Call(ethgo.Address(helper.GetRootchainAdminAddr()), contractAddress, input)
}
func ABITransaction(relayer txrelayer.TxRelayer, key ethgo.Key, artifact *polybft.Artifact, contractAddress ethgo.Address, method string, params ...interface{}) (*ethgo.Receipt, error) {
	input, err := artifact.Abi.GetMethod(method).Encode(params)
	if err != nil {
		return nil, err
	}
	return relayer.SendTransaction(&ethgo.Transaction{
		To:    &contractAddress,
		Input: input,
	}, key)
}

func DeployTransaction(relayer txrelayer.TxRelayer, key ethgo.Key, bytecode []byte) (*ethgo.Receipt, error) {
	return relayer.SendTransaction(&ethgo.Transaction{
		Input: bytecode,
	}, key)
}

func FundValidators(t *testing.T, txRelayer txrelayer.TxRelayer, validators []*polybft.Validator) {
	for i := range validators {
		fundAddr := ethgo.Address(validators[i].Address)
		txn := &ethgo.Transaction{
			To:    &fundAddr,
			Value: big.NewInt(1000000000000000000),
		}

		_, err := txRelayer.SendTransactionLocal(txn)
		if err != nil {
			t.Log(validators[i].Address, "error on funding", err)
		}
	}
}
