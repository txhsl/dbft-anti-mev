package dbft

import "github.com/ethereum/go-ethereum/core/types"

type Block struct {
	header       *types.Header
	transactions []*types.Transaction
	bls          []byte
}
