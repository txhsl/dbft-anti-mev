package message

import (
	"github.com/nspcc-dev/neo-go/pkg/io"
	"github.com/nspcc-dev/neo-go/pkg/util"
)

type Commit struct {
	FinalHash util.Uint256
	// commit.signature is the signature of final block
	Signature []byte
}

func (c Commit) EncodeBinary(w *io.BinWriter) {
	w.WriteBytes(c.FinalHash[:])
	w.WriteBytes(c.Signature)
}

func (c Commit) DecodeBinary(r *io.BinReader) {
	r.ReadBytes(c.FinalHash[:])
	r.ReadBytes(c.Signature)
}
