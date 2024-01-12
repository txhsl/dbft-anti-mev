package dbft

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/nspcc-dev/dbft/payload"
	"github.com/nspcc-dev/neo-go/pkg/util"
	msgutil "github.com/txhsl/dbft-anti-mev/util"
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

	// setup node, note that dkg index start from 1 to 7
	node := NewNode(1, prvs[1], prvs[1].GetPublicKey(), globalpub, dkg.GetScaler())
	neighbors := make([]*Node, 6)
	for i := 0; i < 6; i++ {
		neighbors[i] = NewNode(byte(i+2), prvs[i+2], prvs[i+2].GetPublicKey(), globalpub, dkg.GetScaler())
	}
	node.Connect(neighbors)

	// send an enveloped tx
	tx := types.NewTransaction(1, ZeroAddress, big.NewInt(0), 0, big.NewInt(0), nil)
	node.PendTx(tx)

	// build header and msg
	txs := make([]*types.Transaction, 1)
	hashes := make([]util.Uint256, 1)
	txs[0] = tx
	hashes[0] = util.Uint256(tx.Hash())
	header := &types.Header{
		TxHash: types.DeriveSha(types.Transactions(txs), trie.NewStackTrie(nil)),
	}

	// send a message
	prepareRequest := &msgutil.Payload{
		Message: msgutil.Message{
			Type:           payload.PrepareRequestType,
			ValidatorIndex: 2,
			BlockIndex:     1,
			ViewNumber:     0,
		},
	}
	prepareRequest.SetPayload(msgutil.PrepareRequest{
		SealingProposal: header,
		TxHashes:        hashes,
	})
	prepareRequest.Sign(prvs[2])
	node.HandleMsg(prepareRequest)
}

func TestPrepareResponseHandler(t *testing.T) {

}
func TestAgreeHandler(t *testing.T) {

}
func TestCommitHandler(t *testing.T) {

}
func TestPropose(t *testing.T) {

}

func TestDBFT(t *testing.T) {

}
