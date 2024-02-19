package transaction

import (
	"encoding/binary"
	"math/big"

	"github.com/txhsl/tpke"
)

const (
	SeedLen   = 48 * 4
	Uint64Len = 8
)

type Envelope struct {
	EncryptHeight        uint64
	EncryptedSeed        *tpke.CipherText
	EncryptedTransaction []byte
}

// an envelope costs 200 bytes + tx length
func (e Envelope) ToBytes() []byte {
	b := make([]byte, SeedLen+Uint64Len+len(e.EncryptedTransaction))
	binary.PutUvarint(b, e.EncryptHeight)
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
		EncryptHeight:        h,
		EncryptedSeed:        es,
		EncryptedTransaction: b[Uint64Len+SeedLen:],
	}, nil
}

func (e Envelope) ComputeFee() *big.Int {
	// can be a base fee + bytes fee (in case of big tx), here we return 0
	return big.NewInt(0)
}
