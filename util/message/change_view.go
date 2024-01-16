package message

import (
	"github.com/nspcc-dev/dbft/payload"
	"github.com/nspcc-dev/neo-go/pkg/io"
)

type ChangeView struct {
	NewViewNumber byte
	// timestamp is nanoseconds-precision payload timestamp, exactly like the one
	// that dBFT library operates internally with.
	Timestamp uint64
	Reason    payload.ChangeViewReason
}

func (c ChangeView) EncodeBinary(w *io.BinWriter) {
	w.WriteU64LE(c.Timestamp)
	w.WriteB(byte(c.Reason))
}

func (c ChangeView) DecodeBinary(r *io.BinReader) {
	c.Timestamp = r.ReadU64LE()
	c.Reason = payload.ChangeViewReason(r.ReadB())
}
