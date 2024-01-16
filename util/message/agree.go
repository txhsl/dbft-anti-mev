package message

import "github.com/nspcc-dev/neo-go/pkg/io"

type Agree struct {
	DecryptShare [][]byte
}

func (a Agree) EncodeBinary(w *io.BinWriter) {
	w.WriteArray(a.DecryptShare)
}

func (a Agree) DecodeBinary(r *io.BinReader) {
	r.ReadArray(&a.DecryptShare)
}
