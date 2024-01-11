package util

import (
	"github.com/nspcc-dev/neo-go/pkg/io"
	"github.com/nspcc-dev/neo-go/pkg/util"
)

type PrepareResponse struct {
	PreparationHash util.Uint256
}

func (p PrepareResponse) EncodeBinary(w *io.BinWriter) {
	w.WriteBytes(p.PreparationHash[:])
}

func (p PrepareResponse) DecodeBinary(r *io.BinReader) {
	r.ReadBytes(p.PreparationHash[:])
}
