package dbft

import (
	"io"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/txhsl/tpke"
	"golang.org/x/crypto/sha3"
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

// WorkerSealHash returns the hash of a header prior to it being sealed. WorkerSealHash is
// override to exclude those header fields that will be changed by dBFT during
// block sealing: MixDigest, Nonce and last [crypto.SignatureLength] bytes of
// Extra.
//
// Be careful no to use WorkerSealHash anywhere where "the honest" WorkerSealHash is required.
func WorkerSealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeUnchangeableHeader(hasher, header)
	hasher.(crypto.KeccakState).Read(hash[:])
	return hash
}

// encodeUnchangeableHeader encodes those header fields that won't be changed by
// dBFT during block sealing: every header field except MixDigest, Nonce and last
// [crypto.SignatureLength] bytes of Extra.
func encodeUnchangeableHeader(w io.Writer, header *types.Header) {
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		// Do not include validators addresses into hashable part.
		header.Extra, // Yes, this will panic if extra is too short.
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	if header.WithdrawalsHash != nil {
		panic("unexpected withdrawal hash value in dbft")
	}
	if err := rlp.Encode(w, enc); err != nil {
		panic("can't encode: " + err.Error())
	}
}
