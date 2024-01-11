package util

import (
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/nspcc-dev/dbft/payload"
	"github.com/nspcc-dev/neo-go/pkg/io"
	"github.com/txhsl/tpke"
)

const (
	extraSeal = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for a single signer seal

	AgreeType payload.MessageType = 0x22
)

type (
	Message struct {
		Type           payload.MessageType
		BlockIndex     uint64
		ValidatorIndex byte
		ViewNumber     byte

		payload io.Serializable
	}

	// Payload is a type for consensus-related messages.
	Payload struct {
		Message
		witness []byte
	}
)

// ViewNumber implements the payload.ConsensusPayload interface.
func (p Payload) ViewNumber() byte {
	return p.Message.ViewNumber
}

// SetViewNumber implements the payload.ConsensusPayload interface.
func (p *Payload) SetViewNumber(view byte) {
	p.Message.ViewNumber = view
}

// Type implements the payload.ConsensusPayload interface.
func (p Payload) Type() payload.MessageType {
	return payload.MessageType(p.Message.Type)
}

// SetType implements the payload.ConsensusPayload interface.
func (p *Payload) SetType(t payload.MessageType) {
	p.Message.Type = t
}

// Payload implements the payload.ConsensusPayload interface.
func (p Payload) Payload() any {
	return p.payload
}

// SetPayload implements the payload.ConsensusPayload interface.
func (p *Payload) SetPayload(pl any) {
	p.payload = pl.(io.Serializable)
}

// GetChangeView implements the payload.ConsensusPayload interface.
func (p Payload) GetChangeView() payload.ChangeView { return p.payload.(payload.ChangeView) }

// GetPrepareRequest implements the payload.ConsensusPayload interface.
func (p Payload) GetPrepareRequest() payload.PrepareRequest {
	return p.payload.(payload.PrepareRequest)
}

// GetPrepareResponse implements the payload.ConsensusPayload interface.
func (p Payload) GetPrepareResponse() payload.PrepareResponse {
	return p.payload.(payload.PrepareResponse)
}

// GetCommit implements the payload.ConsensusPayload interface.
func (p Payload) GetCommit() payload.Commit { return p.payload.(payload.Commit) }

// GetRecoveryRequest implements the payload.ConsensusPayload interface.
func (p Payload) GetRecoveryRequest() payload.RecoveryRequest {
	return p.payload.(payload.RecoveryRequest)
}

// GetRecoveryMessage implements the payload.ConsensusPayload interface.
func (p Payload) GetRecoveryMessage() payload.RecoveryMessage {
	return p.payload.(payload.RecoveryMessage)
}

// ValidatorIndex implements the payload.ConsensusPayload interface.
func (p Payload) ValidatorIndex() uint16 {
	return uint16(p.Message.ValidatorIndex)
}

// SetValidatorIndex implements the payload.ConsensusPayload interface.
func (p *Payload) SetValidatorIndex(i uint16) {
	p.Message.ValidatorIndex = byte(i)
}

// Height implements the payload.ConsensusPayload interface.
func (p Payload) Height() uint32 {
	return uint32(p.Message.BlockIndex)
}

// SetHeight implements the payload.ConsensusPayload interface.
func (p *Payload) SetHeight(h uint32) {
	p.Message.BlockIndex = uint64(h)
}

func (p *Payload) Sign(prv *tpke.PrivateKey) {
	b, err := rlp.EncodeToBytes(p.Message)
	if err != nil {
		panic("failed to encode msg to RLP")
	}
	share := prv.SignShare(b)
	s, err := rlp.EncodeToBytes(share)
	if err != nil {
		panic("failed to encode sig share to RLP")
	}
	p.witness = s
}

func (p *Payload) Verify(pub *tpke.PublicKey) bool {
	b, err := rlp.EncodeToBytes(p.Message)
	if err != nil {
		panic("failed to encode msg to RLP")
	}
	var sig *tpke.Signature
	err = rlp.DecodeBytes(p.witness, sig)
	if err != nil {
		panic("failed to decode sig RLP")
	}
	return pub.Verify(b, sig)
}
