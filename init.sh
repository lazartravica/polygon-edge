#!/bin/bash

sudo rm -r test-rootchain
rm genesis.json
rm -r test-chain-*

go run . polybft-secrets --data-dir test-chain- --num 4
go run . rootchain server
