package facilitator

import (
	"encoding/hex"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/coinbase/x402/go/extensions/erc20approvalgassponsor"
	"github.com/coinbase/x402/go/mechanisms/evm"
)

// approveSelector is the 4-byte function selector for ERC-20 approve(address,uint256).
// keccak256("approve(address,uint256)") = 0x095ea7b3...
var approveSelector = []byte{0x09, 0x5e, 0xa7, 0xb3}

// ValidateErc20ApprovalForPayment validates the ERC-20 approval extension data.
// Returns an empty string if valid, or an error reason string on failure.
func ValidateErc20ApprovalForPayment(info *erc20approvalgassponsor.Info, payer, tokenAddress string) string {
	// Step 1: Validate info format
	if !erc20approvalgassponsor.ValidateInfo(info) {
		return ErrErc20ApprovalInvalidFormat
	}

	// Step 2: Verify from matches payer
	if !strings.EqualFold(info.From, payer) {
		return ErrErc20ApprovalFromMismatch
	}

	// Step 3: Verify asset matches token
	if !strings.EqualFold(info.Asset, tokenAddress) {
		return ErrErc20ApprovalAssetMismatch
	}

	// Step 4: Verify spender is Permit2
	if !strings.EqualFold(info.Spender, evm.PERMIT2Address) {
		return ErrErc20ApprovalWrongSpender
	}

	// Step 5: Decode and parse the RLP transaction
	txHex := strings.TrimPrefix(info.SignedTransaction, "0x")
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return ErrErc20ApprovalTxParseFailed
	}

	tx := new(types.Transaction)
	if err := tx.UnmarshalBinary(txBytes); err != nil {
		return ErrErc20ApprovalTxParseFailed
	}

	// Step 6: Verify transaction target is the token contract
	if tx.To() == nil || !strings.EqualFold(tx.To().Hex(), tokenAddress) {
		return ErrErc20ApprovalWrongTarget
	}

	// Step 7: Verify the approve(address,uint256) selector
	data := tx.Data()
	if len(data) < 4 {
		return ErrErc20ApprovalWrongSelector
	}
	for i, b := range approveSelector {
		if data[i] != b {
			return ErrErc20ApprovalWrongSelector
		}
	}

	// Step 8: Decode spender from calldata (first 32-byte slot after selector, last 20 bytes)
	if len(data) < 36 {
		return ErrErc20ApprovalWrongCalldata
	}
	calldataSpender := common.BytesToAddress(data[4:36]) // last 20 bytes of first 32-byte param slot
	if !strings.EqualFold(calldataSpender.Hex(), evm.PERMIT2Address) {
		return ErrErc20ApprovalWrongCalldata
	}

	// Step 9: Verify the transaction was signed by payer
	chainID := tx.ChainId()
	signer := types.LatestSignerForChainID(chainID)
	from, err := types.Sender(signer, tx)
	if err != nil {
		return ErrErc20ApprovalInvalidSig
	}
	if !strings.EqualFold(from.Hex(), payer) {
		return ErrErc20ApprovalSignerMismatch
	}

	return ""
}
