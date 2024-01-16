package transaction

import (
	"encoding/binary"

	"github.com/txhsl/tpke"
)

const (
	SeedLen   = 48 * 8
	Uint64Len = 8
)

type Envelope struct {
	ExpireHeight         uint64
	EncryptedSeed        *tpke.CipherText
	EncryptedTransaction []byte
}

func (e Envelope) ToBytes() []byte {
	b := make([]byte, SeedLen+Uint64Len+len(e.EncryptedTransaction))
	binary.PutUvarint(b, e.ExpireHeight)
	copy(b[Uint64Len:Uint64Len+SeedLen], e.EncryptedSeed.ToBytes())
	copy(b[Uint64Len+SeedLen:], e.EncryptedTransaction)
	return b
}

func BytesToEnvelope(b []byte) (*Envelope, error) {
	h, _ := binary.Uvarint(b[:Uint64Len])
	es, err := tpke.BytesToCipherText(b[Uint64Len : Uint64Len+SeedLen])
	if err != nil {
		return nil, err
	}
	return &Envelope{
		ExpireHeight:         h,
		EncryptedSeed:        es,
		EncryptedTransaction: b[Uint64Len+SeedLen:],
	}, nil
}
