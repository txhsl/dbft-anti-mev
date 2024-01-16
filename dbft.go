package dbft

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/nspcc-dev/dbft/payload"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/txhsl/dbft-anti-mev/util/message"
	"github.com/txhsl/dbft-anti-mev/util/transaction"
	"github.com/txhsl/tpke"
)

type Node struct {
	index           byte
	prv             *tpke.PrivateKey
	pub             *tpke.PublicKey
	neighborPubKeys map[uint16]*tpke.PublicKey
	globalPubKey    *tpke.PublicKey
	scaler          int

	height         uint64
	view           byte
	viewLock       bool
	txList         []*types.Transaction
	preblockHash   common.Hash
	finalBlockHash common.Hash

	prepareResponses map[uint16]*message.PrepareResponse
	agrees           map[uint16]*message.Agree
	commits          map[uint16]*message.Commit
	changeViews      map[uint16]*message.ChangeView

	neighbors      []chan<- *message.Payload
	messageHandler chan *message.Payload
	txPool         []*types.Transaction
}

func NewNode(index byte, prv *tpke.PrivateKey, pub *tpke.PublicKey, globalPub *tpke.PublicKey, scaler int) *Node {
	return &Node{
		index:            index,
		prv:              prv,
		pub:              pub,
		neighborPubKeys:  make(map[uint16]*tpke.PublicKey),
		globalPubKey:     globalPub,
		scaler:           scaler,
		height:           0,
		view:             0,
		viewLock:         false,
		neighbors:        make([]chan<- *message.Payload, 0),
		messageHandler:   make(chan *message.Payload, 100),
		txPool:           make([]*types.Transaction, 0),
		txList:           make([]*types.Transaction, 0),
		prepareResponses: make(map[uint16]*message.PrepareResponse),
		agrees:           make(map[uint16]*message.Agree),
		commits:          make(map[uint16]*message.Commit),
		changeViews:      make(map[uint16]*message.ChangeView),
	}
}

func (n *Node) GetIndex() byte {
	return n.index
}

func (n *Node) GetHandler() chan<- *message.Payload {
	return n.messageHandler
}

func (n *Node) GetPublicKey() *tpke.PublicKey {
	return n.pub
}

func (n *Node) Connect(ns []*Node) {
	for _, v := range ns {
		if v.index == n.index {
			continue
		}
		n.neighbors = append(n.neighbors, v.GetHandler())
		n.neighborPubKeys[uint16(v.GetIndex())] = v.GetPublicKey()
	}
}

func (n *Node) PendTx(tx *types.Transaction) {
	n.txPool = append(n.txPool, tx)
}

func (n *Node) Propose() {
	txhashes := make([]util.Uint256, len(n.txPool))
	for i, v := range n.txPool {
		txhashes[i] = util.Uint256(v.Hash())
	}
	txhash := types.DeriveSha(types.Transactions(n.txPool), trie.NewStackTrie(nil))
	h := &types.Header{
		TxHash: txhash,
	}
	n.preblockHash = h.Hash()
	n.txList = n.txPool

	// broadcast prepare request
	msg := &message.Payload{
		Message: message.Message{
			Type:           payload.PrepareRequestType,
			ValidatorIndex: n.index,
			BlockIndex:     n.height + 1,
			ViewNumber:     n.view,
		},
	}
	msg.SetPayload(message.PrepareRequest{
		SealingProposal: h,
		TxHashes:        txhashes,
	})
	msg.Sign(n.prv)
	for i := 0; i < len(n.neighbors); i++ {
		n.neighbors[i] <- msg
	}
}

func (n *Node) HandleMsg(m *message.Payload) {
	// drop some scam
	if m.BlockIndex != n.height+1 {
		return
	}
	if m.ViewNumber() != n.view {
		return
	}
	if !m.Verify(n.neighborPubKeys[m.ValidatorIndex()]) {
		return
	}

	// handle
	if m.Type() == payload.PrepareRequestType {
		prepareRequest := m.Payload().(message.PrepareRequest)
		h := prepareRequest.SealingProposal
		txhs := prepareRequest.TxHashes

		// verify request, deal anti-mev tx as normal tx (consider all tx are enveloped tx in this code)
		txsChecked := true
		txs := make([]*types.Transaction, 0)
		for _, v := range txhs {
			f := false
			for _, tx := range n.txPool {
				if util.Uint256(tx.Hash()) == v {
					f = true
					txs = append(txs, tx)
					break
				}
			}
			if !f {
				txsChecked = false
			}
		}
		hChecked := types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil)) == h.TxHash

		// for further use
		n.txList = txs
		n.preblockHash = h.Hash()

		// broadcast response
		if txsChecked && hChecked {
			msg := &message.Payload{
				Message: message.Message{
					Type:           payload.PrepareResponseType,
					ValidatorIndex: n.index,
					BlockIndex:     m.BlockIndex,
					ViewNumber:     m.ViewNumber(),
				},
			}
			msg.SetPayload(message.PrepareResponse{
				PreparationHash: util.Uint256(h.Hash()),
			})
			msg.Sign(n.prv)
			for i := 0; i < len(n.neighbors); i++ {
				n.neighbors[i] <- msg
			}
		}
	} else if m.Type() == payload.PrepareResponseType {
		prepareResponse := m.Payload().(message.PrepareResponse)

		// verify response
		checked := prepareResponse.PreparationHash == util.Uint256(n.preblockHash)

		// count vote
		if checked {
			n.prepareResponses[m.ValidatorIndex()] = &prepareResponse
		}

		if len(n.prepareResponses) == len(n.neighbors)*2/3+1 {
			// generate decrypt share for anti-mev tx
			s := make([]*tpke.DecryptionShare, 0)
			for _, v := range n.txList {
				envelope, err := transaction.BytesToEnvelope(v.Data())
				if err != nil {
					continue
				}
				s = append(s, n.prv.DecryptShare(envelope.EncryptedSeed))
			}
			share := EncodeDecryptionShare(s)

			// broadcast agree
			msg := &message.Payload{
				Message: message.Message{
					Type:           message.AgreeType,
					ValidatorIndex: n.index,
					BlockIndex:     m.BlockIndex,
					ViewNumber:     m.ViewNumber(),
				},
			}
			msg.SetPayload(message.Agree{
				DecryptShare: share,
			})
			msg.Sign(n.prv)
			for i := 0; i < len(n.neighbors); i++ {
				n.neighbors[i] <- msg
			}
		}
	} else if m.Type() == message.AgreeType {
		agree := m.Payload().(message.Agree)

		// count vote
		n.agrees[m.ValidatorIndex()] = &agree

		if len(n.agrees) == len(n.neighbors)*2/3+1 {
			// try decrypt tx data
			es := make([]*transaction.Envelope, 0)
			cs := make([]*tpke.CipherText, 0)
			for _, v := range n.txList {
				envelope, err := transaction.BytesToEnvelope(v.Data())
				if err != nil {
					continue
				}
				es = append(es, envelope)
				cs = append(cs, envelope.EncryptedSeed)
			}
			inputs := make(map[int][]*tpke.DecryptionShare)
			for i, v := range n.agrees {
				share := DecodeDecryptionShare(v.DecryptShare)
				inputs[int(i)] = share
			}
			seeds, err := tpke.Decrypt(cs, inputs, n.globalPubKey, len(n.neighbors)*2/3, n.scaler)
			if err != nil {
				// wait for another agree message until change view
				return
			}

			// build the final block
			// Temporarily use the same block here, let just verify the decrypted data
			n.finalBlockHash = n.preblockHash
			for i, v := range es {
				data, err := tpke.AESDecrypt(seeds[i], v.EncryptedTransaction)
				if err != nil {
					continue
				}
				fmt.Println(string(data))
			}

			// lock change view
			n.viewLock = true

			// broadcast commit
			msg := &message.Payload{
				Message: message.Message{
					Type:           payload.CommitType,
					ValidatorIndex: n.index,
					BlockIndex:     m.BlockIndex,
					ViewNumber:     m.ViewNumber(),
				},
			}

			msg.SetPayload(message.Commit{
				FinalHash: util.Uint256(n.finalBlockHash),
				Signature: EncodeSignatureShare(n.prv.SignShare(n.finalBlockHash.Bytes())),
			})
			msg.Sign(n.prv)
			for i := 0; i < len(n.neighbors); i++ {
				n.neighbors[i] <- msg
			}
		}
	} else if m.Type() == payload.CommitType {
		commit := m.Payload().(message.Commit)

		// verify header and sig
		checked := commit.FinalHash == util.Uint256(n.finalBlockHash)
		sig := DecodeSignature(commit.Signature)
		checked = checked && n.neighborPubKeys[m.ValidatorIndex()].VerifySig(n.finalBlockHash.Bytes(), sig)

		// increase local height and reset dbft
		if checked {
			n.commits[m.ValidatorIndex()] = &commit
		}

		if len(n.commits) == len(n.neighbors)*2/3+1 {
			// compute the bls signature
			shares := make(map[int]*tpke.SignatureShare, len(n.commits))
			for i, v := range n.commits {
				shares[int(i)] = DecodeSignatureShare(v.Signature)
			}
			// the output is not used here, but should be applyed to block in practice
			_, err := tpke.AggregateAndVerify(n.globalPubKey, n.finalBlockHash.Bytes(), len(n.neighbors)*2/3+1, shares, n.scaler)
			if err != nil {
				// wait for another agree message until change view
				return
			}

			n.height += 1
			n.view = 0
			n.viewLock = false
		}
	} else if m.Type() == payload.ChangeViewType {
		changeView := m.Payload().(message.ChangeView)

		// count vote
		if changeView.NewViewNumber == n.view+1 && !n.viewLock {
			n.changeViews[m.ValidatorIndex()] = &changeView
		}

		// change view
		if len(n.changeViews) > len(n.neighbors)*2/3 {
			n.view += 1
		}
	} else {
		panic("UNKNOWN MSG")
	}
}

func (n *Node) EventLoop() {
	for {
		select {
		case m := <-n.messageHandler:
			n.HandleMsg(m)
		}
	}
}
