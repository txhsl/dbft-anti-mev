package dbft

import (
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/nspcc-dev/dbft/payload"
	"github.com/nspcc-dev/neo-go/pkg/util"
	msgutil "github.com/txhsl/dbft-anti-mev/util"
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
	preblockHash   []byte
	finalBlockHash []byte

	prepareResponses map[uint16]*msgutil.PrepareResponse
	agrees           map[uint16]*msgutil.Agree
	commits          map[uint16]*msgutil.Commit
	changeViews      map[uint16]*msgutil.ChangeView

	neighbors      []chan<- *msgutil.Payload
	messageHandler chan *msgutil.Payload
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
		neighbors:        make([]chan<- *msgutil.Payload, 0),
		messageHandler:   make(chan *msgutil.Payload, 100),
		txPool:           make([]*types.Transaction, 0),
		txList:           make([]*types.Transaction, 0),
		prepareResponses: make(map[uint16]*msgutil.PrepareResponse),
		agrees:           make(map[uint16]*msgutil.Agree),
		commits:          make(map[uint16]*msgutil.Commit),
		changeViews:      make(map[uint16]*msgutil.ChangeView),
	}
}

func (n *Node) GetIndex() byte {
	return n.index
}

func (n *Node) GetHandler() chan<- *msgutil.Payload {
	return n.messageHandler
}

func (n *Node) GetPublicKey() *tpke.PublicKey {
	return n.pub
}

func (n *Node) Connect(ns []*Node) {
	for _, v := range ns {
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

	// broadcast prepare request
	msg := &msgutil.Payload{
		Message: msgutil.Message{
			Type:           payload.PrepareRequestType,
			ValidatorIndex: n.index,
			BlockIndex:     n.height + 1,
			ViewNumber:     n.view + 1,
		},
	}
	msg.SetPayload(msgutil.PrepareRequest{
		SealingProposal: h,
		TxHashes:        txhashes,
	})
	msg.Sign(n.prv)
	for i := 0; i < len(n.neighbors); i++ {
		n.neighbors[i] <- msg
	}
}

func (n *Node) HandleMsg(m *msgutil.Payload) {
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
		prepareRequest := m.Payload().(msgutil.PrepareRequest)
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
		n.preblockHash = h.Hash().Bytes()

		// broadcast response
		if txsChecked && hChecked {
			msg := &msgutil.Payload{
				Message: msgutil.Message{
					Type:           payload.PrepareResponseType,
					ValidatorIndex: n.index,
					BlockIndex:     m.BlockIndex,
					ViewNumber:     m.ViewNumber(),
				},
			}
			msg.SetPayload(msgutil.PrepareResponse{
				PreparationHash: util.Uint256(h.Hash()),
			})
			msg.Sign(n.prv)
			for i := 0; i < len(n.neighbors); i++ {
				n.neighbors[i] <- msg
			}
		}
	} else if m.Type() == payload.PrepareResponseType {
		prepareResponse := m.Payload().(msgutil.PrepareResponse)

		// verify response
		checked := prepareResponse.PreparationHash == util.Uint256(n.preblockHash)

		// count vote
		if checked {
			n.prepareResponses[m.ValidatorIndex()] = &prepareResponse
		}

		if len(n.prepareResponses) > len(n.neighbors)*2/3 {
			// decrypt anti-mev tx
			s := make([]*tpke.DecryptionShare, 0)
			for i, v := range n.txList {
				s[i] = n.prv.DecryptShare(DecodeCiphertext(v.Data()))
			}
			share := EncodeDecryptionShare(s)

			// broadcast agree
			for i := 0; i < len(n.neighbors); i++ {
				msg := &msgutil.Payload{
					Message: msgutil.Message{
						Type:           msgutil.AgreeType,
						ValidatorIndex: n.index,
						BlockIndex:     m.BlockIndex,
						ViewNumber:     m.ViewNumber(),
					},
				}
				msg.SetPayload(msgutil.Agree{
					DecryptShare: share,
				})
				msg.Sign(n.prv)
				for i := 0; i < len(n.neighbors); i++ {
					n.neighbors[i] <- msg
				}
			}
		}
	} else if m.Type() == msgutil.AgreeType {
		agree := m.Payload().(msgutil.Agree)

		// count vote
		n.agrees[m.ValidatorIndex()] = &agree

		if len(n.agrees) > len(n.neighbors)*2/3 {
			// try decrypt tx data
			c := make([]*tpke.CipherText, len(n.txList))
			for i, v := range n.txList {
				c[i] = DecodeCiphertext(v.Data())
			}
			inputs := make(map[int][]*tpke.DecryptionShare)
			for i, v := range n.agrees {
				share := DecodeDecryptionShare(v.DecryptShare)
				inputs[int(i)] = share
			}
			data, err := tpke.Decrypt(c, inputs, n.globalPubKey, len(n.neighbors)*2/3, n.scaler)
			if err != nil {
				// wait for another agree message until change view
				return
			}

			// build the final block
			// Temporarily use the same block here, let just verify the decrypted data
			n.finalBlockHash = n.preblockHash
			for _, v := range data {
				fmt.Println(v)
			}

			// lock change view
			n.viewLock = true

			// broadcast commit
			msg := &msgutil.Payload{
				Message: msgutil.Message{
					Type:           payload.CommitType,
					ValidatorIndex: n.index,
					BlockIndex:     m.BlockIndex,
					ViewNumber:     m.ViewNumber(),
				},
			}

			msg.SetPayload(msgutil.Commit{
				FinalHash: util.Uint256(n.finalBlockHash),
				Signature: EncodeSignatureShare(n.prv.SignShare(n.finalBlockHash)),
			})
			msg.Sign(n.prv)
			for i := 0; i < len(n.neighbors); i++ {
				n.neighbors[i] <- msg
			}
		}
	} else if m.Type() == payload.CommitType {
		commit := m.Payload().(msgutil.Commit)

		// verify header and sig
		checked := commit.FinalHash == util.Uint256(n.finalBlockHash)
		sig := DecodeSignature(commit.Signature)
		checked = checked && n.neighborPubKeys[m.ValidatorIndex()].VerifySig(n.finalBlockHash, sig)

		// increase local height and reset dbft
		if checked {
			n.commits[m.ValidatorIndex()] = &commit
		}

		if len(n.commits) > len(n.neighbors)*2/3 {
			// compute the bls signature
			shares := make(map[int]*tpke.SignatureShare, len(n.commits))
			for i, v := range n.commits {
				shares[int(i)] = DecodeSignatureShare(v.Signature)
			}
			// the output is not used here, but should be applyed to block in practice
			_, err := tpke.AggregateAndVerify(n.globalPubKey, n.finalBlockHash, len(n.neighbors)*2/3, shares, n.scaler)
			if err != nil {
				// wait for another agree message until change view
				return
			}

			n.height += 1
			n.view = 0
			n.viewLock = false
		}
	} else if m.Type() == payload.ChangeViewType {
		changeView := m.Payload().(msgutil.ChangeView)

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

func (n *Node) MsgLoop() {
	for {
		select {
		case m := <-n.messageHandler:
			n.HandleMsg(m)
		}
	}
}
