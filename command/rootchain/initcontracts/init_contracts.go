package initcontracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/umbracle/ethgo"
	"github.com/umbracle/ethgo/abi"
	"github.com/umbracle/ethgo/jsonrpc"

	"github.com/0xPolygon/polygon-edge/chain"
	"github.com/0xPolygon/polygon-edge/command"
	"github.com/0xPolygon/polygon-edge/command/rootchain/helper"
	"github.com/0xPolygon/polygon-edge/consensus/polybft"
	bls "github.com/0xPolygon/polygon-edge/consensus/polybft/signer"
	"github.com/0xPolygon/polygon-edge/contracts"
	"github.com/0xPolygon/polygon-edge/helper/hex"
	"github.com/0xPolygon/polygon-edge/txrelayer"
	"github.com/0xPolygon/polygon-edge/types"
)

const (
	contractsDeploymentTitle = "[ROOTCHAIN - CONTRACTS DEPLOYMENT]"

	stateSenderName       = "StateSender"
	checkpointManagerName = "CheckpointManager"
	blsName               = "BLS"
	bn256G2Name           = "BN256G2"
)

var (
	params initContractsParams

	initCheckpointManager, _ = abi.NewMethod("function initialize(" +
		// BLS contract address
		"address newBls," +
		// BN256G2 contract address
		"address newBn256G2," +
		// domain used for BLS signing
		"bytes32 newDomain," +
		// rootchain validator set
		"tuple(address _address, uint256[4] blsKey, uint256 votingPower)[] newValidatorSet)")

	// metadataPopulatorMap maps rootchain contract names to callback
	// which populates appropriate field in the RootchainMetadata
	metadataPopulatorMap = map[string]func(*polybft.RootchainConfig, types.Address){
		stateSenderName: func(rootchainConfig *polybft.RootchainConfig, addr types.Address) {
			rootchainConfig.StateSenderAddress = addr
		},
		checkpointManagerName: func(rootchainConfig *polybft.RootchainConfig, addr types.Address) {
			rootchainConfig.CheckpointManagerAddress = addr
		},
		blsName: func(rootchainConfig *polybft.RootchainConfig, addr types.Address) {
			rootchainConfig.BLSAddress = addr
		},
		bn256G2Name: func(rootchainConfig *polybft.RootchainConfig, addr types.Address) {
			rootchainConfig.BN256G2Address = addr
		},
	}
)

// GetCommand returns the rootchain emit command
func GetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "init-contracts",
		Short:   "Deploys and initializes required smart contracts on the rootchain",
		PreRunE: runPreRun,
		Run:     runCommand,
	}

	setFlags(cmd)

	return cmd
}

func setFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&params.contractsPath,
		contractsPathFlag,
		contracts.ContractsRootFolder,
		"Root directory path containing POS smart contracts",
	)

	cmd.Flags().StringVar(
		&params.manifestPath,
		manifestPathFlag,
		defaultManifestPath,
		"Manifest file path, which contains metadata",
	)

	cmd.Flags().StringVar(
		&params.adminKey,
		adminKeyFlag,
		helper.DefaultPrivateKeyRaw,
		"Hex encoded private key of the account which deploys rootchain contracts",
	)

	cmd.Flags().StringVar(
		&params.jsonRPCAddress,
		jsonRPCFlag,
		"http://127.0.0.1:8545",
		"The JSON RPC rootchain IP address (e.g. http://127.0.0.1:8545)",
	)
}

func runPreRun(cmd *cobra.Command, _ []string) error {
	if err := cmd.MarkFlagRequired(manifestPathFlag); err != nil {
		return err
	}

	return params.validateFlags()
}

func runCommand(cmd *cobra.Command, _ []string) {
	outputter := command.InitializeOutputter(cmd)
	defer outputter.WriteOutput()

	outputter.WriteCommandResult(&messageResult{
		Message: fmt.Sprintf("%s started...", contractsDeploymentTitle),
	})

	client, err := jsonrpc.NewClient(params.jsonRPCAddress)
	if err != nil {
		outputter.SetError(fmt.Errorf("failed to initialize JSON RPC client for provided IP address: %s: %w",
			params.jsonRPCAddress, err))

		return
	}

	manifest, err := polybft.LoadManifest(params.manifestPath)
	if err != nil {
		outputter.SetError(fmt.Errorf("failed to read manifest: %w", err))

		return
	}

	if manifest.RootchainConfig != nil {
		code, err := client.Eth().GetCode(ethgo.Address(manifest.RootchainConfig.StateSenderAddress), ethgo.Latest)
		if err != nil {
			outputter.SetError(fmt.Errorf("failed to check if rootchain contracts are deployed: %w", err))

			return
		} else if code != "0x" {
			outputter.SetCommandResult(&messageResult{
				Message: fmt.Sprintf("%s contracts are already deployed. Aborting.", contractsDeploymentTitle),
			})

			return
		}
	}

	if err := helper.InitRootchainAdminKey(params.adminKey); err != nil {
		outputter.SetError(err)

		return
	}

	if err := deployContracts(outputter, client, manifest); err != nil {
		outputter.SetError(fmt.Errorf("failed to deploy rootchain contracts: %w", err))

		return
	}

	outputter.SetCommandResult(&messageResult{
		Message: fmt.Sprintf("%s finished. All contracts are successfully deployed and initialized.",
			contractsDeploymentTitle),
	})
}

func deployContracts(outputter command.OutputFormatter, client *jsonrpc.Client, manifest *polybft.Manifest) error {
	// if the bridge contract is not created, we have to deploy all the contracts
	txRelayer, err := txrelayer.NewTxRelayer(txrelayer.WithClient(client))
	if err != nil {
		return fmt.Errorf("failed to initialize tx relayer: %w", err)
	}

	rootchainAdminKey := helper.GetRootchainAdminKey()
	// if admin key is equal to the test private key, then we assume we are working in dev mode
	// and therefore need to fund that account
	if params.adminKey == helper.DefaultPrivateKeyRaw {
		// fund account
		rootchainAdminAddr := rootchainAdminKey.Address()
		txn := &ethgo.Transaction{To: &rootchainAdminAddr, Value: big.NewInt(1000000000000000000)}
		_, err = txRelayer.SendTransactionLocal(txn)

		if err != nil {
			return err
		}
	}

	deployContracts := []struct {
		name string
		path string
	}{
		{
			name: stateSenderName,
			path: "root/StateSender.sol",
		},
		{
			name: checkpointManagerName,
			path: "root/CheckpointManager.sol",
		},
		{
			name: blsName,
			path: "common/BLS.sol",
		},
		{
			name: bn256G2Name,
			path: "common/BN256G2.sol",
		},
	}

	rootchainConfig := &polybft.RootchainConfig{}
	manifest.RootchainConfig = rootchainConfig
	rootchainConfig.AdminAddress = types.Address(rootchainAdminKey.Address())

	for _, contract := range deployContracts {
		bytecode, err := readContractBytecode(params.contractsPath, contract.path, contract.name)
		if err != nil {
			return err
		}

		txn := &ethgo.Transaction{
			To:    nil, // contract deployment
			Input: bytecode,
		}

		receipt, err := txRelayer.SendTransaction(txn, rootchainAdminKey)
		if err != nil {
			return err
		}

		contractAddr := types.Address(receipt.ContractAddress)

		populatorFn, ok := metadataPopulatorMap[contract.name]
		if !ok {
			return fmt.Errorf("rootchain metadata populator not registered for contract '%s'", contract.name)
		}

		populatorFn(manifest.RootchainConfig, contractAddr)

		outputter.WriteCommandResult(newDeployContractsResult(contract.name, contractAddr, receipt.TransactionHash))
	}

	if err := manifest.Save(params.manifestPath); err != nil {
		return fmt.Errorf("failed to save manifest data: %w", err)
	}

	if err := initializeCheckpointManager(txRelayer, rootchainAdminKey, manifest); err != nil {
		return err
	}

	outputter.WriteCommandResult(&messageResult{
		Message: fmt.Sprintf("%s CheckpointManager contract is initialized", contractsDeploymentTitle),
	})

	return nil
}

// initializeCheckpointManager invokes initialize function on CheckpointManager smart contract
func initializeCheckpointManager(
	txRelayer txrelayer.TxRelayer,
	rootchainAdminKey ethgo.Key,
	manifest *polybft.Manifest) error {
	validatorSetMap, err := validatorSetToABISlice(manifest.GenesisValidators)
	if err != nil {
		return fmt.Errorf("failed to convert validators to map: %w", err)
	}

	initCheckpointInput, err := initCheckpointManager.Encode(
		[]interface{}{
			manifest.RootchainConfig.BLSAddress,
			manifest.RootchainConfig.BN256G2Address,
			bls.GetDomain(),
			validatorSetMap,
		})

	if err != nil {
		return fmt.Errorf("failed to encode parameters for CheckpointManager.initialize. error: %w", err)
	}

	checkpointManagerAddress := ethgo.Address(manifest.RootchainConfig.CheckpointManagerAddress)
	txn := &ethgo.Transaction{
		To:    &checkpointManagerAddress,
		Input: initCheckpointInput,
	}

	receipt, err := txRelayer.SendTransaction(txn, rootchainAdminKey)
	if err != nil {
		return fmt.Errorf("failed to send transaction to CheckpointManager. error: %w", err)
	}

	if receipt.Status != uint64(types.ReceiptSuccess) {
		return errors.New("failed to initialize CheckpointManager")
	}

	return nil
}

// initializeCheckpointManager invokes initialize function on CheckpointManager smart contract
func validatorSetToABISlice(validators []*polybft.Validator) ([]map[string]interface{}, error) {
	genesisValidators := make([]*polybft.Validator, len(validators))
	copy(genesisValidators, validators)
	sort.Slice(genesisValidators, func(i, j int) bool {
		return bytes.Compare(genesisValidators[i].Address.Bytes(), genesisValidators[j].Address.Bytes()) < 0
	})

	validatorSetMap := make([]map[string]interface{}, len(genesisValidators))

	for i, validatorInfo := range genesisValidators {
		blsKey, err := validatorInfo.UnmarshalBLSPublicKey()
		if err != nil {
			return nil, err
		}

		validatorSetMap[i] = map[string]interface{}{
			"_address":    validatorInfo.Address,
			"blsKey":      blsKey.ToBigInt(),
			"votingPower": chain.ConvertWeiToTokensAmount(validatorInfo.Balance),
		}
	}

	return validatorSetMap, nil
}

func readContractBytecode(rootPath, contractPath, contractName string) ([]byte, error) {
	_, fileName := filepath.Split(contractPath)

	absolutePath, err := filepath.Abs(rootPath)
	if err != nil {
		return nil, err
	}

	filePath := filepath.Join(absolutePath, contractPath, strings.TrimSuffix(fileName, ".sol")+".json")

	data, err := ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, err
	}

	var artifact struct {
		Bytecode string `json:"bytecode"`
	}

	if err := json.Unmarshal(data, &artifact); err != nil {
		return nil, err
	}

	return hex.MustDecodeHex(artifact.Bytecode), nil
}
