package message

import "github.com/nspcc-dev/neo-go/pkg/io"

type Finalize struct {
	DecryptShare [][]byte // there will be different shares for every tx, each costs 96 bytes
}

func (a Finalize) EncodeBinary(w *io.BinWriter) {
	w.WriteArray(a.DecryptShare)
}

func (a Finalize) DecodeBinary(r *io.BinReader) {
	r.ReadArray(&a.DecryptShare)
}
