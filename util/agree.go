package util

import "github.com/nspcc-dev/neo-go/pkg/io"

type Agree struct {
	DecryptShare []byte
}

func (a Agree) EncodeBinary(w *io.BinWriter) {
	w.WriteBytes(a.DecryptShare)
}

func (a Agree) DecodeBinary(r *io.BinReader) {
	r.ReadBytes(a.DecryptShare)
}
