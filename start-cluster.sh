#!/bin/bash

go run . genesis --block-gas-limit 10000000 --validator-set-size=4 --consensus polybft --epoch-size 5 --bridge-json-rpc
go run . rootchain init-contracts
go run . rootchain fund --data-dir test-chain- --num 4

go run . server --data-dir ./test-chain-1 --chain genesis.json --grpc-address :5001 --libp2p :30301 --jsonrpc :9545 --seal --log-level DEBUG &
go run . server --data-dir ./test-chain-2 --chain genesis.json --grpc-address :5002 --libp2p :30302 --jsonrpc :10002 --seal --log-level DEBUG &
go run . server --data-dir ./test-chain-3 --chain genesis.json --grpc-address :5003 --libp2p :30303 --jsonrpc :10003 --seal --log-level DEBUG &
go run . server --data-dir ./test-chain-4 --chain genesis.json --grpc-address :5004 --libp2p :30304 --jsonrpc :10004 --seal --log-level DEBUG
