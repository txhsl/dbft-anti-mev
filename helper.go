package dbft

import (
	"github.com/txhsl/tpke"
)

func EncodeSignatureShare(s *tpke.SignatureShare) []byte {
	return s.ToBytes()
}

func DecodeSignatureShare(b []byte) *tpke.SignatureShare {
	s, err := tpke.BytesToSigShare(b)
	if err != nil {
		panic("failed to decode sig share")
	}
	return s
}

func DecodeSignature(b []byte) *tpke.Signature {
	s, err := tpke.BytesToSig(b)
	if err != nil {
		panic("failed to decode sig")
	}
	return s
}

func EncodeDecryptionShare(ss []*tpke.DecryptionShare) [][]byte {
	bs := make([][]byte, len(ss))
	for i := 0; i < len(ss); i++ {
		bs[i] = ss[i].ToBytes()
	}
	return bs
}

func DecodeDecryptionShare(bs [][]byte) []*tpke.DecryptionShare {
	ss := make([]*tpke.DecryptionShare, len(bs))
	for i := 0; i < len(bs); i++ {
		s, err := tpke.BytesToDecryptionShare(bs[i])
		if err != nil {
			panic("failed to decode share")
		}
		ss[i] = s
	}
	return ss
}
