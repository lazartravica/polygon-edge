package contractsapi

import (
	"github.com/0xPolygon/polygon-edge/consensus/polybft"
)

var (
	Rootchain     *polybft.Artifact
	ExitHelper    *polybft.Artifact
	L1Exit        *polybft.Artifact
	L2StateSender *polybft.Artifact
)

func init() {
	scpath := "../core-contracts/artifacts/contracts/"
	var err error
	Rootchain, err = polybft.ReadArtifact(scpath, "root/CheckpointManager.sol", "CheckpointManager")
	if err != nil {
		panic(err)
	}
	ExitHelper, err = polybft.ReadArtifact(scpath, "root/ExitHelper.sol", "ExitHelper")
	if err != nil {
		panic(err)
	}

	L1Exit, err = polybft.ReadArtifact(scpath, "root/L1.sol", "L1")
	if err != nil {
		panic(err)
	}

	L2StateSender, err = polybft.ReadArtifact(scpath, "child/L2StateSender.sol", "L2StateSender")
	if err != nil {
		panic(err)
	}
}
