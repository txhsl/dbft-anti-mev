package util

import "github.com/nspcc-dev/neo-go/pkg/io"

type Agree struct {
	DecryptShare []byte
	// agree.signature is the signature of decrypt share
	Signature [extraSeal]byte
}

func (a Agree) EncodeBinary(w *io.BinWriter) {
	w.WriteBytes(a.DecryptShare)
	w.WriteBytes(a.Signature[:])
}

func (a Agree) DecodeBinary(r *io.BinReader) {
	r.ReadBytes(a.DecryptShare)
	r.ReadBytes(a.Signature[:])
}
