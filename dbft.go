package dbft

import (
	"bytes"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/nspcc-dev/dbft/payload"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/txhsl/dbft-anti-mev/util/message"
	"github.com/txhsl/dbft-anti-mev/util/transaction"
	"github.com/txhsl/tpke"
)

// the address of mev fee receiver, here use zero address
var ZeroAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")

type Node struct {
	index            byte             // validator index
	prv              *tpke.PrivateKey // private key for decryption and signature
	pub              *tpke.PublicKey  // public key for verification
	neighborPubKeys  map[uint16]*tpke.PublicKey
	globalPubKey     *tpke.PublicKey // public key for users' encryption
	keyEnabledHeight uint64          // the beginning point of height that the global public key is used in encryption and decryption
	scaler           int             // a scaler factor generated by DKG for computation speed up

	blocks     map[uint64]*Block    // blocks
	height     uint64               // current height
	view       byte                 // view number
	viewLock   bool                 // a lock to stop change view after decryption sharing
	txList     []*types.Transaction // transactions selected for next block
	envelopNum int                  // number of enveloped tx in txList
	proposal   *types.Header        // consensus proposal as a header

	// message pool
	prepareResponses map[uint16]*message.PrepareResponse
	finalizes        map[uint16]*message.Finalize
	dbftFinalized    bool
	commits          map[uint16]*message.Commit
	dbftCommited     bool
	changeViews      map[uint16]*message.ChangeView

	// P2P channel, handler and mempool
	neighbors      []chan<- *message.Payload
	messageHandler chan *message.Payload
	legacyPool     []*types.Transaction // the mempool for legacy tx
	envelopePool   []*types.Transaction // an independent mempool only handles enveloped tx
}

// set up a node based on dkg
func NewNode(index byte, prv *tpke.PrivateKey, pub *tpke.PublicKey, globalPub *tpke.PublicKey, keyEnabledHeight uint64, scaler int) *Node {
	return &Node{
		index:            index,
		prv:              prv,
		pub:              pub,
		neighborPubKeys:  make(map[uint16]*tpke.PublicKey),
		globalPubKey:     globalPub,
		keyEnabledHeight: keyEnabledHeight,
		scaler:           scaler,
		blocks:           make(map[uint64]*Block),
		height:           0,
		view:             0,
		viewLock:         false,
		neighbors:        make([]chan<- *message.Payload, 0),
		messageHandler:   make(chan *message.Payload, 100),
		legacyPool:       make([]*types.Transaction, 0),
		envelopePool:     make([]*types.Transaction, 0),
		txList:           nil,
		envelopNum:       0,
		proposal:         nil,
		prepareResponses: make(map[uint16]*message.PrepareResponse),
		finalizes:        make(map[uint16]*message.Finalize),
		dbftFinalized:    false,
		commits:          make(map[uint16]*message.Commit),
		dbftCommited:     false,
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

// add a legacy tx to mempool
func (n *Node) PendLegacyTx(tx *types.Transaction) error {
	n.legacyPool = append(n.legacyPool, tx)
	return nil
}

// add a enveloped tx to mempool
func (n *Node) PendEnvelopedTx(tx *types.Transaction) error {
	// only resolvable envelope can be added to this mempool
	envelope, err := transaction.BytesToEnvelope(tx.Data())
	if err != nil {
		return err
	}
	if envelope.EncryptHeight < n.keyEnabledHeight {
		return errors.New("encryption expired")
	}
	if envelope.ComputeFee().Cmp(tx.Value()) > 0 {
		return errors.New("not enough service fee")
	}
	if tx.To().Cmp(ZeroAddress) != 0 {
		return errors.New("wrong payment target")
	}
	// verify that user provides a random r as he commits
	// CNs will only focus and decrypt the random r to generate the seed point
	// so if the r commitment is valid but the transaction decryption failed,
	// the envelope will be dropped and we cannot say any CN is malicious
	err = envelope.EncryptedSeed.Verify()
	if err != nil {
		return err
	}
	n.envelopePool = append(n.envelopePool, tx)
	return nil
}

func (n *Node) RefreshEnvelopePool() error {
	for i, v := range n.envelopePool {
		envelope, err := transaction.BytesToEnvelope(v.Data())
		if err != nil {
			return err
		}
		if envelope.EncryptHeight < n.keyEnabledHeight {
			n.envelopePool = append(n.envelopePool[:i], n.envelopePool[i+1:]...)
		}
	}
	return nil
}

// propose a new block and start consensus
func (n *Node) Propose() {
	// propose the tx sequence
	txhashes := make([]util.Uint256, len(n.envelopePool)+len(n.legacyPool))
	for i, v := range n.envelopePool {
		txhashes[i] = util.Uint256(v.Hash())
	}
	for i, v := range n.legacyPool {
		txhashes[len(n.envelopePool)+i] = util.Uint256(v.Hash())
	}

	// execute all carrier txs, to ensure all enveloped txs can be and have been paid for decryption
	// ......
	// ...... stateRoot = execute(n.envelopePool)
	// ......
	// a temporary state root with receipt root can be generated after above execution, but here I only describe it

	// build a pre-header for consensus of the tx sequence
	txhash := types.DeriveSha(types.Transactions(append(n.envelopePool, n.legacyPool...)), trie.NewStackTrie(nil))
	h := &types.Header{
		TxHash: txhash,
		// Root: stateRoot,
		// ......
	}
	n.proposal = h
	n.txList = append(n.envelopePool, n.legacyPool...)
	n.envelopNum = len(n.envelopePool)

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
		envelopNum := 0
		txs := make([]*types.Transaction, 0)
		for _, v := range txhs {
			f := false
			for _, tx := range n.envelopePool {
				if util.Uint256(tx.Hash()) == v {
					f = true
					txs = append(txs, tx)
					envelopNum += 1
					break
				}
			}
			for _, tx := range n.legacyPool {
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

		// execute and verify envelope carriers locally
		// ......
		// ...... stateRoot = execute(txs[:envelopNum])
		// ...... if stateRoot != h.Root { }
		// ......

		// for further use
		n.txList = txs
		n.envelopNum = envelopNum
		n.proposal = h

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
		checked := prepareResponse.PreparationHash == util.Uint256(n.proposal.Hash())

		// count vote
		if checked {
			n.prepareResponses[m.ValidatorIndex()] = &prepareResponse
		}

		if len(n.prepareResponses) == len(n.neighbors)*2/3+1 {
			// generate decrypt share for anti-mev tx
			s := make([]*tpke.DecryptionShare, 0)
			for i, v := range n.txList {
				if i < n.envelopNum {
					envelope, err := transaction.BytesToEnvelope(v.Data())
					if err != nil {
						continue
					}
					s = append(s, n.prv.DecryptShare(envelope.EncryptedSeed))
				}
			}
			share := EncodeDecryptionShare(s)

			// lock change view
			n.viewLock = true

			// broadcast finalize
			msg := &message.Payload{
				Message: message.Message{
					Type:           message.FinalizeType,
					ValidatorIndex: n.index,
					BlockIndex:     m.BlockIndex,
					ViewNumber:     m.ViewNumber(),
				},
			}
			msg.SetPayload(message.Finalize{
				DecryptShare: share,
			})
			msg.Sign(n.prv)
			for i := 0; i < len(n.neighbors); i++ {
				n.neighbors[i] <- msg
			}
		}
	} else if m.Type() == message.FinalizeType {
		finalize := m.Payload().(message.Finalize)

		// count vote
		n.finalizes[m.ValidatorIndex()] = &finalize

		if len(n.finalizes) >= len(n.neighbors)*2/3+1 && !n.dbftFinalized {
			// try decrypt tx data
			bs := make([][]byte, 0)           // encrypted transactions
			cs := make([]*tpke.CipherText, 0) // seeds for decryption
			for i, v := range n.txList {
				if i < n.envelopNum {
					envelope, err := transaction.BytesToEnvelope(v.Data())
					if err != nil {
						continue
					}
					bs = append(bs, envelope.EncryptedTransaction)
					cs = append(cs, envelope.EncryptedSeed)
				}
			}
			inputs := make(map[int][]*tpke.DecryptionShare)
			for i, v := range n.finalizes {
				share := DecodeDecryptionShare(v.DecryptShare)
				inputs[int(i)] = share
			}
			seeds, err := tpke.Decrypt(cs, inputs, n.globalPubKey, len(n.neighbors)*2/3, int(n.scaler))
			if err != nil {
				// wait for another finalize message and will not change view
				return
			}
			n.dbftFinalized = true

			// build the final block
			finalTxList := make([]*types.Transaction, 0)
			for i, v := range bs {
				data, err := tpke.AESDecrypt(seeds[i], v)
				if err != nil {
					continue
				}
				tx := new(types.Transaction)
				s := rlp.NewStream(bytes.NewBuffer(data), 0)
				err = tx.DecodeRLP(s)
				if err != nil {
					continue
				}
				finalTxList = append(finalTxList, tx)
			}

			// now we can have the final tx list, executed carriers at first, then decrypted envelopes, then legacy txs
			finalTxList = append(n.txList[:n.envelopNum], finalTxList...)
			finalTxList = append(finalTxList, n.txList[n.envelopNum:]...)
			n.proposal.TxHash = types.DeriveSha(types.Transactions(finalTxList), trie.NewStackTrie(nil))

			// execute all txs to get necessary info to build the final block
			// ......
			// ...... stateRoot = execute(finalTxList)
			// ...... n.proposal.Root = stateRoot
			// ......

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
				FinalHash: util.Uint256(n.proposal.Hash()),
				Signature: EncodeSignatureShare(n.prv.SignShare(n.proposal.Hash().Bytes())),
			})
			msg.Sign(n.prv)
			for i := 0; i < len(n.neighbors); i++ {
				n.neighbors[i] <- msg
			}
		}
	} else if m.Type() == payload.CommitType {
		commit := m.Payload().(message.Commit)

		// verify header and sig
		checked := commit.FinalHash == util.Uint256(n.proposal.Hash())
		sig := DecodeSignature(commit.Signature)
		checked = checked && n.neighborPubKeys[m.ValidatorIndex()].VerifySig(n.proposal.Hash().Bytes(), sig)

		// increase local height and reset dbft
		if checked {
			n.commits[m.ValidatorIndex()] = &commit
		}

		if len(n.commits) >= len(n.neighbors)*2/3+1 && !n.dbftCommited {
			// compute the bls signature
			shares := make(map[int]*tpke.SignatureShare, len(n.commits))
			for i, v := range n.commits {
				shares[int(i)] = DecodeSignatureShare(v.Signature)
			}
			// the global public key is necessary for verification
			sig, err := tpke.AggregateAndVerifySig(n.globalPubKey, n.proposal.Hash().Bytes(), len(n.neighbors)*2/3+1, shares, int(n.scaler))
			if err != nil {
				// wait for another commit message and will not change view
				return
			}
			n.dbftCommited = true

			// finish
			n.blocks[n.height+1] = &Block{
				Header:       n.proposal,
				Transactions: n.txList,
				Signature:    sig.ToBytes(),
			}
			n.height += 1
			n.view = 0
			n.viewLock = false

			// reset for next round
			n.txList = nil
			n.proposal = nil
			n.legacyPool = make([]*types.Transaction, 0)
			n.envelopePool = make([]*types.Transaction, 0)
			n.prepareResponses = make(map[uint16]*message.PrepareResponse)
			n.finalizes = make(map[uint16]*message.Finalize)
			n.dbftFinalized = false
			n.commits = make(map[uint16]*message.Commit)
			n.dbftCommited = false
			n.changeViews = make(map[uint16]*message.ChangeView)

			// broadcast the new block
			// ......
		}
	} else if m.Type() == payload.ChangeViewType {
		changeView := m.Payload().(message.ChangeView)

		// count vote
		if changeView.NewViewNumber == n.view+1 && !n.viewLock {
			n.changeViews[m.ValidatorIndex()] = &changeView
		}

		// change view
		if len(n.changeViews) == len(n.neighbors)*2/3+1 {
			n.view += 1
			n.txList = nil
			n.proposal = nil
			n.prepareResponses = make(map[uint16]*message.PrepareResponse)
			n.finalizes = make(map[uint16]*message.Finalize)
			n.commits = make(map[uint16]*message.Commit)
			n.changeViews = make(map[uint16]*message.ChangeView)
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
