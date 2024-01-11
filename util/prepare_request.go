package util

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/nspcc-dev/neo-go/pkg/io"
	"github.com/nspcc-dev/neo-go/pkg/util"
)

type PrepareRequest struct {
	SealingProposal *types.Header
	TxHashes        []util.Uint256

	// Fields that should be included into PrepareRequest for its verification:
	ParentSealHash common.Hash
	ParentExtra    []byte
}

func (p PrepareRequest) EncodeBinary(w *io.BinWriter) {
	b, err := rlp.EncodeToBytes(p)
	if err != nil {
		w.Err = fmt.Errorf("failed to encode PrepareRequest to RLP: %w", err)
		return
	}
	w.WriteVarBytes(b)
}

func (p PrepareRequest) DecodeBinary(r *io.BinReader) {
	b := r.ReadVarBytes()
	if r.Err != nil {
		return
	}
	err := rlp.DecodeBytes(b, p)
	if err != nil {
		r.Err = fmt.Errorf("failed to decode PrepareRequest RLP: %w", err)
	}
}
