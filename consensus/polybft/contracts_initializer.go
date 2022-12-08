package polybft

import (
	"encoding/hex"
	"fmt"
	"math/big"

	bls "github.com/0xPolygon/polygon-edge/consensus/polybft/signer"
	"github.com/0xPolygon/polygon-edge/contracts"
	"github.com/0xPolygon/polygon-edge/state"
	"github.com/0xPolygon/polygon-edge/types"
	"github.com/umbracle/ethgo/abi"
)

const (
	// safe numbers for the test
	newEpochReward   = 1
	newMinStake      = 1
	newMinDelegation = 1
)

var (
	initCallStaking, _ = abi.NewMethod("function initialize(" +
		"uint256 newEpochReward," +
		"uint256 newMinStake," +
		"uint256 newMinDelegation," +
		"address[] validatorAddresses," +
		"uint256[4][] validatorPubkeys," +
		"uint256[] validatorStakes," +
		"address newBls," +
		"uint256[2] newMessage," +
		"address governance)")

	initNativeTokenMethod, _ = abi.NewMethod("function initialize(" +
		"address predicate_," +
		"string name_," +
		"string symbol_)")

	nativeTokenName   = "Polygon"
	nativeTokenSymbol = "MATIC"
)

func getInitChildValidatorSetInput(validators []*Validator, governanceAddr types.Address) ([]byte, error) {
	validatorAddresses := make([]types.Address, len(validators))
	validatorPubkeys := make([][4]*big.Int, len(validators))
	validatorStakes := make([]*big.Int, len(validators))

	for i, validator := range validators {
		blsKey, err := hex.DecodeString(validator.BlsKey)
		if err != nil {
			return nil, err
		}

		pubKey, err := bls.UnmarshalPublicKey(blsKey)
		if err != nil {
			return nil, err
		}

		pubKeyBig := pubKey.ToBigInt()

		validatorPubkeys[i] = pubKeyBig
		validatorAddresses[i] = validator.Address
		validatorStakes[i] = validator.Balance
	}

	registerMessage, err := bls.MarshalMessageToBigInt([]byte(contracts.PolyBFTRegisterMessage))
	if err != nil {
		return nil, err
	}

	input, err := initCallStaking.Encode([]interface{}{
		big.NewInt(newEpochReward),
		big.NewInt(newMinStake),
		big.NewInt(newMinDelegation),
		validatorAddresses,
		validatorPubkeys,
		validatorStakes,
		contracts.BLSContract, // address of the deployed BLS contract
		registerMessage,
		governanceAddr,
	})
	if err != nil {
		return nil, err
	}

	return input, nil
}

func initContract(to types.Address, input []byte, contractName string, transition *state.Transition) error {
	result := transition.Call2(contracts.SystemCaller, to, input,
		big.NewInt(0), 100_000_000)

	if result.Failed() {
		if result.Reverted() {
			unpackedRevert, err := abi.UnpackRevertError(result.ReturnValue)
			if err == nil {
				fmt.Printf("%v.initialize %v\n", contractName, unpackedRevert)
			}
		}

		return result.Err
	}

	return nil
}