package dbft

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/nspcc-dev/neo-go/pkg/util"
)

type Block struct {
	Header       *types.Header
	Transactions []*types.Transaction
	Signature    []byte
}

// Hash implements Block interface. Hash returns unsealed block hash that doesn't
// include Nonce, MixDigest fields and Extra's signature part, thus, can be used
// only for worker's block identification and information purposes.
func (b *Block) Hash() util.Uint256 {
	return util.Uint256(WorkerSealHash(b.Header))
}
