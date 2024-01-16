package transaction

import (
	"github.com/txhsl/tpke"
)

type Envelope struct {
	EncryptedSeed        *tpke.CipherText
	EncryptedTransaction []byte
}

func (e Envelope) ToBytes() []byte {
	seedLen := 48 * 8
	b := make([]byte, seedLen+len(e.EncryptedTransaction))
	copy(b[:seedLen], e.EncryptedSeed.ToBytes())
	copy(b[seedLen:], e.EncryptedTransaction)
	return b
}

func BytesToEnvelope(b []byte) (*Envelope, error) {
	seedLen := 48 * 8
	es, err := tpke.BytesToCipherText(b[:seedLen])
	if err != nil {
		return nil, err
	}
	return &Envelope{
		EncryptedSeed:        es,
		EncryptedTransaction: b[seedLen:],
	}, nil
}
