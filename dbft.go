package dbft

import (
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

	height           uint64
	view             byte
	prepareResponses map[uint16]*msgutil.PrepareResponse
	agrees           map[uint16]*msgutil.Agree
	commits          map[uint16]*msgutil.Commit
	changeViews      map[uint16]*msgutil.ChangeView

	neighbors      []chan<- msgutil.Payload
	messageHandler chan msgutil.Payload
	txPool         []*types.Transaction
}

func NewNode(index byte, prv *tpke.PrivateKey, pub *tpke.PublicKey, globalPub *tpke.PublicKey) *Node {
	return &Node{
		index:            index,
		prv:              prv,
		pub:              pub,
		neighborPubKeys:  make(map[uint16]*tpke.PublicKey),
		globalPubKey:     globalPub,
		height:           0,
		view:             0,
		neighbors:        make([]chan<- msgutil.Payload, 0),
		messageHandler:   make(chan msgutil.Payload),
		txPool:           make([]*types.Transaction, 0),
		prepareResponses: make(map[uint16]*msgutil.PrepareResponse),
		agrees:           make(map[uint16]*msgutil.Agree),
		commits:          make(map[uint16]*msgutil.Commit),
		changeViews:      make(map[uint16]*msgutil.ChangeView),
	}
}

func (n *Node) GetHandler() chan<- msgutil.Payload {
	return n.messageHandler
}

func (n *Node) Connect(ns []*Node) {
	for _, v := range ns {
		n.neighbors = append(n.neighbors, v.GetHandler())
	}
}

func (n *Node) PendTx(tx *types.Transaction) {
	n.txPool = append(n.txPool, tx)
}

func (n *Node) Propose() *Block {
	return nil
}

func (n *Node) MsgLoop() {
	for {
		select {
		case m := <-n.messageHandler:
			// drop something
			if m.BlockIndex != n.height+1 {
				continue
			}
			if m.ViewNumber() != n.view {
				continue
			}
			if !m.Verify(n.neighborPubKeys[m.ValidatorIndex()]) {
				continue
			}

			// handle
			if m.Type() == payload.PrepareRequestType {
				prepareRequest := m.Payload().(msgutil.PrepareRequest)
				h := prepareRequest.SealingProposal
				txhs := prepareRequest.TxHashes

				// verify request, deal anti-mev tx as normal tx
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

				// broadcast response
				if txsChecked && hChecked {
					msg := msgutil.Payload{
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
				checked := prepareResponse.PreparationHash != util.Uint256{}

				// count vote
				if checked {
					n.prepareResponses[m.ValidatorIndex()] = &prepareResponse
				}

				if len(n.prepareResponses) > len(n.neighbors)*2/3 {
					// decrypt anti-mev tx

					// broadcast agree
					for i := 0; i < len(n.neighbors); i++ {
						msg := msgutil.Payload{
							Message: msgutil.Message{
								Type:           msgutil.AgreeType,
								ValidatorIndex: n.index,
								BlockIndex:     m.BlockIndex,
								ViewNumber:     m.ViewNumber(),
							},
						}
						msg.SetPayload(msgutil.Agree{
							DecryptShare: nil,
							Signature:    nil,
						})
						msg.Sign(n.prv)
						for i := 0; i < len(n.neighbors); i++ {
							n.neighbors[i] <- msg
						}
					}
				}
			} else if m.Type() == msgutil.AgreeType {
				agree := m.Payload().(msgutil.Agree)

				// verify share
				checked := agree.DecryptShare != nil

				// lock change view

				// decrypt tx data

				// build the final block

				// count vote
				if checked {
					n.agrees[m.ValidatorIndex()] = &agree
				}

				// broadcast commit
				if len(n.agrees) > len(n.neighbors)*2/3 {
					msg := msgutil.Payload{
						Message: msgutil.Message{
							Type:           payload.CommitType,
							ValidatorIndex: n.index,
							BlockIndex:     m.BlockIndex,
							ViewNumber:     m.ViewNumber(),
						},
					}
					msg.SetPayload(msgutil.Commit{
						FinalHash: nil,
						Signature: nil,
					})
					msg.Sign(n.prv)
					for i := 0; i < len(n.neighbors); i++ {
						n.neighbors[i] <- msg
					}
				}
			} else if m.Type() == payload.CommitType {
				commit := m.Payload().(msgutil.Commit)

				// verify header and sig
				checked := commit.FinalHash != util.Uint256{}

				// increase local height and reset dbft
				if checked {
					n.commits[m.ValidatorIndex()] = &commit
				}

				if len(n.commits) > len(n.neighbors)*2/3 {
					n.height += 1
					n.view = 0
				}
			} else if m.Type() == payload.ChangeViewType {
				changeView := m.Payload().(msgutil.ChangeView)

				// count vote
				if changeView.NewViewNumber == n.view+1 {
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
	}
}
