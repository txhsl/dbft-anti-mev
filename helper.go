package dbft

import (
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/txhsl/tpke"
)

func EncodeSignatureShare(s *tpke.SignatureShare) []byte {
	sig, err := rlp.EncodeToBytes(s)
	if err != nil {
		panic("failed to encode sig share to RLP")
	}
	return sig
}

func DecodeSignatureShare(b []byte) *tpke.SignatureShare {
	var s *tpke.SignatureShare
	err := rlp.DecodeBytes(b, s)
	if err != nil {
		panic("failed to decode sig share RLP")
	}
	return s
}

func DecodeSignature(b []byte) *tpke.Signature {
	var s *tpke.Signature
	err := rlp.DecodeBytes(b, s)
	if err != nil {
		panic("failed to decode sig  RLP")
	}
	return s
}

func EncodeCiphertext(c *tpke.CipherText) []byte {
	b, err := rlp.EncodeToBytes(c)
	if err != nil {
		panic("failed to encode ciphertext to RLP")
	}
	return b
}

func DecodeCiphertext(b []byte) *tpke.CipherText {
	var c *tpke.CipherText
	err := rlp.DecodeBytes(b, c)
	if err != nil {
		panic("failed to decode ciphertext RLP")
	}
	return c
}

func EncodeDecryptionShare(c []*tpke.DecryptionShare) []byte {
	b, err := rlp.EncodeToBytes(c)
	if err != nil {
		panic("failed to encode share to RLP")
	}
	return b
}

func DecodeDecryptionShare(b []byte) []*tpke.DecryptionShare {
	var s []*tpke.DecryptionShare
	err := rlp.DecodeBytes(b, s)
	if err != nil {
		panic("failed to decode share RLP")
	}
	return s
}
