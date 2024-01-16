package dbft

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/nspcc-dev/dbft/payload"
	"github.com/nspcc-dev/neo-go/pkg/util"
	"github.com/txhsl/dbft-anti-mev/util/message"
	"github.com/txhsl/dbft-anti-mev/util/transaction"
	"github.com/txhsl/tpke"
)

var ZeroAddress = common.HexToAddress("0x0000000000000000000000000000000000000000")

// The scaler works well when the network size is smaller than 9, other wise overflow
func TestPrepareRequestHandler(t *testing.T) {
	dkg := tpke.NewDKG(7, 4)
	dkg.Prepare()
	err := dkg.Verify()
	if err != nil {
		t.Fatalf(err.Error())
	}
	prvs := dkg.GetPrivateKeys()
	globalpub := dkg.PublishGlobalPublicKey()

	// setup node, note that dkg index start from 1 to 7, due to mathematical reason
	nodes := make([]*Node, 7)
	for i := 0; i < 7; i++ {
		nodes[i] = NewNode(byte(i+1), prvs[i+1], prvs[i+1].GetPublicKey(), globalpub, dkg.GetScaler())
	}
	nodes[0].Connect(nodes)

	// send a tx
	tx := types.NewTransaction(1, ZeroAddress, big.NewInt(0), 0, big.NewInt(0), nil)
	nodes[0].PendTx(tx)

	// build header and msg
	txs := make([]*types.Transaction, 1)
	hashes := make([]util.Uint256, 1)
	txs[0] = tx
	hashes[0] = util.Uint256(tx.Hash())
	header := &types.Header{
		TxHash: types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil)),
	}

	// send a message
	prepareRequest := &message.Payload{
		Message: message.Message{
			Type:           payload.PrepareRequestType,
			ValidatorIndex: 2,
			BlockIndex:     1,
			ViewNumber:     0,
		},
	}
	prepareRequest.SetPayload(message.PrepareRequest{
		SealingProposal: header,
		TxHashes:        hashes,
	})
	prepareRequest.Sign(prvs[2])
	nodes[0].HandleMsg(prepareRequest)
}

func TestDBFT(t *testing.T) {
	dkg := tpke.NewDKG(7, 4)
	dkg.Prepare()
	err := dkg.Verify()
	if err != nil {
		t.Fatalf(err.Error())
	}
	prvs := dkg.GetPrivateKeys()
	globalpub := dkg.PublishGlobalPublicKey()

	// setup node, note that dkg index start from 1 to 7, due to mathematical reason
	nodes := make([]*Node, 7)
	for i := 0; i < 7; i++ {
		nodes[i] = NewNode(byte(i+1), prvs[i+1], prvs[i+1].GetPublicKey(), globalpub, dkg.GetScaler())
	}
	for i := 0; i < 7; i++ {
		nodes[i].Connect(nodes)
	}

	// create an enveloped tx, use string as an example
	msg := "This is some necessary info of an enveloped tx"
	seed := tpke.RandPG1()
	es := globalpub.Encrypt(seed)
	et, err := tpke.AESEncrypt(seed, []byte(msg))
	if err != nil {
		t.Fatalf(err.Error())
	}
	envelope := &transaction.Envelope{
		EncryptedSeed:        es,
		EncryptedTransaction: et,
	}

	// wrap the enveloped tx into a normal transfer
	tx := types.NewTransaction(1, ZeroAddress, big.NewInt(0), 0, big.NewInt(0), envelope.ToBytes())
	for i := 0; i < 7; i++ {
		nodes[i].PendTx(tx)
	}

	// start a consensus
	nodes[0].Propose()

	// handle prepare request
	for i := 0; i < 7; i++ {
		nodes[i].EventLoopOnce()
	}

	// handle prepare response
	for j := 0; j < 6; j++ {
		nodes[0].EventLoopOnce()
	}
	for i := 1; i < 7; i++ {
		for j := 0; j < 5; j++ {
			nodes[i].EventLoopOnce()
		}
	}

	// handle agree
	for i := 0; i < 7; i++ {
		for j := 0; j < 6; j++ {
			nodes[i].EventLoopOnce()
		}
	}

	// handle commit
	for i := 0; i < 7; i++ {
		for j := 0; j < 6; j++ {
			nodes[i].EventLoopOnce()
		}
	}

	for i := 0; i < 7; i++ {
		if nodes[i].height < 1 {
			t.Fatalf("invalid consensus")
		}
	}
}

func (n *Node) EventLoopOnce() {
	if len(n.messageHandler) == 0 {
		return
	}
	m := <-n.messageHandler
	n.HandleMsg(m)
}
