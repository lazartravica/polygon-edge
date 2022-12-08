package polybftmanifest

import (
	"fmt"
	"path"
	"strings"

	"github.com/0xPolygon/polygon-edge/command"
	"github.com/0xPolygon/polygon-edge/command/genesis"
	"github.com/0xPolygon/polygon-edge/consensus/polybft"
	"github.com/0xPolygon/polygon-edge/types"
	"github.com/spf13/cobra"
)

const (
	manifestPathFlag      = "path"
	premineValidatorsFlag = "premine-validators"
	validatorsFlag        = "validators"
	validatorsPathFlag    = "validators-path"
	validatorsPrefixFlag  = "validators-prefix"

	defaultValidatorPrefixPath = "test-chain-"
	defaultManifestPath        = "./manifest.json"

	nodeIDLength       = 53
	ecdsaAddressLength = 42
	blsKeyLength       = 2
)

var (
	params = &manifestInitParams{}
)

// GetCommand returns the rootchain emit command
func GetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "polybft-manifest",
		Short: "Initializes manifest file",
		// PreRunE: runPreRun,
		Run: runCommand,
	}

	setFlags(cmd)

	return cmd
}

func setFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(
		&params.manifestPath,
		manifestPathFlag,
		defaultManifestPath,
		"the file path where manifest file is going to be stored",
	)

	cmd.Flags().StringVar(
		&params.validatorsPath,
		validatorsPathFlag,
		"",
		"prefix path for polybft validator folder directory",
	)

	cmd.Flags().StringVar(
		&params.validatorsPrefixPath,
		validatorsPrefixFlag,
		defaultValidatorPrefixPath,
		"prefix path for polybft validator folder directory",
	)

	cmd.Flags().StringArrayVar(
		&params.validators,
		validatorsFlag,
		[]string{},
		"validators defined by user throughout a parameter (format: <node id>:<ECDSA address>:<public BLS key>)",
	)

	cmd.Flags().StringVar(
		&params.premineValidators,
		premineValidatorsFlag,
		command.DefaultPremineBalance,
		"the amount which will be pre-mined to all the validators",
	)

	cmd.MarkFlagsMutuallyExclusive(validatorsFlag, validatorsPathFlag)
	cmd.MarkFlagsMutuallyExclusive(validatorsFlag, validatorsPrefixFlag)
}

func runCommand(cmd *cobra.Command, _ []string) {
	outputter := command.InitializeOutputter(cmd)
	defer outputter.WriteOutput()

	validators, err := params.getValidatorAccounts()
	if err != nil {
		outputter.SetError(fmt.Errorf("failed to get validator accounts: %w", err))

		return
	}

	manifest := &polybft.Manifest{GenesisValidators: validators}
	if err = manifest.Save(params.manifestPath); err != nil {
		outputter.SetError(fmt.Errorf("failed to save manifest file '%s': %w", params.manifestPath, err))

		return
	}

	outputter.SetCommandResult(params.getResult())
}

type manifestInitParams struct {
	manifestPath         string
	validatorsPath       string
	validatorsPrefixPath string
	premineValidators    string
	validators           []string
}

// getValidatorAccounts gathers validator accounts info either from CLI or from provided local storage
func (p *manifestInitParams) getValidatorAccounts() ([]*polybft.Validator, error) {
	balance, err := types.ParseUint256orHex(&params.premineValidators)
	if err != nil {
		return nil, fmt.Errorf("provided invalid premine validators balance: %s", params.premineValidators)
	}

	if len(p.validators) > 0 {
		validators := make([]*polybft.Validator, len(p.validators))
		for i, validator := range p.validators {
			parts := strings.Split(validator, ":")

			if len(parts) != 3 {
				return nil, fmt.Errorf("expected 3 parts provided in the following format "+
					"<nodeId:ECDSA address:blsKey>, but got %d part(s)",
					len(parts))
			}

			if len(parts[0]) != nodeIDLength {
				return nil, fmt.Errorf("invalid node id: %s", parts[0])
			}

			if len(parts[1]) != ecdsaAddressLength {
				return nil, fmt.Errorf("invalid address: %s", parts[1])
			}

			if len(parts[2]) < blsKeyLength {
				return nil, fmt.Errorf("invalid bls key: %s", parts[2])
			}

			validators[i] = &polybft.Validator{
				NodeID:  parts[0],
				Address: types.StringToAddress(parts[1]),
				BlsKey:  parts[2],
				Balance: balance,
			}
		}

		return validators, nil
	}

	validatorsPath := p.validatorsPath
	if validatorsPath == "" {
		validatorsPath = path.Dir(p.manifestPath)
	}

	validators, err := genesis.ReadValidatorsByRegexp(validatorsPath, p.validatorsPrefixPath)
	if err != nil {
		return nil, err
	}

	for _, v := range validators {
		v.Balance = balance
	}

	return validators, nil
}

func (p *manifestInitParams) getResult() command.CommandResult {
	return &result{
		message: fmt.Sprintf("Manifest file written to %s\n", p.manifestPath),
	}
}

type result struct {
	message string
}

func (r *result) GetOutput() string {
	return r.message
}