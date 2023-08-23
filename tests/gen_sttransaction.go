// Code generated by github.com/fjl/gencodec. DO NOT EDIT.

package tests

import (
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
)

var _ = (*stTransactionMarshaling)(nil)

// MarshalJSON marshals as JSON.
func (s stTransaction) MarshalJSON() ([]byte, error) {
	type stTransaction struct {
		GasPrice             *math.HexOrDecimal256 `json:"gasPrice"`
		MaxFeePerGas         *math.HexOrDecimal256 `json:"maxFeePerGas,omitempty"`
		MaxPriorityFeePerGas *math.HexOrDecimal256 `json:"maxPriorityFeePerGas,omitempty"`
		Nonce                math.HexOrDecimal64   `json:"nonce"`
		To                   string                `json:"to"`
		Data                 []string              `json:"data"`
		AccessLists          []*types.AccessList   `json:"accessLists,omitempty"`
		GasLimit             []math.HexOrDecimal64 `json:"gasLimit"`
		Value                []string              `json:"value"`
		PrivateKey           hexutil.Bytes         `json:"secretKey"`
		Sender               common.Address        `json:"sender,omitempty"`
		BlobVersionedHashes  []common.Hash         `json:"blobVersionedHashes,omitempty"`
		BlobGasFeeCap        *math.HexOrDecimal256 `json:"maxFeePerBlobGas,omitempty"`
	}
	var enc stTransaction
	enc.GasPrice = (*math.HexOrDecimal256)(s.GasPrice)
	enc.MaxFeePerGas = (*math.HexOrDecimal256)(s.MaxFeePerGas)
	enc.MaxPriorityFeePerGas = (*math.HexOrDecimal256)(s.MaxPriorityFeePerGas)
	enc.Nonce = math.HexOrDecimal64(s.Nonce)
	enc.To = s.To
	enc.Data = s.Data
	enc.AccessLists = s.AccessLists
	if s.GasLimit != nil {
		enc.GasLimit = make([]math.HexOrDecimal64, len(s.GasLimit))
		for k, v := range s.GasLimit {
			enc.GasLimit[k] = math.HexOrDecimal64(v)
		}
	}
	enc.Value = s.Value
	enc.PrivateKey = s.PrivateKey
	enc.Sender = s.Sender
	enc.BlobVersionedHashes = s.BlobVersionedHashes
	enc.BlobGasFeeCap = (*math.HexOrDecimal256)(s.BlobGasFeeCap)
	return json.Marshal(&enc)
}

// UnmarshalJSON unmarshals from JSON.
func (s *stTransaction) UnmarshalJSON(input []byte) error {
	type stTransaction struct {
		GasPrice             *math.HexOrDecimal256 `json:"gasPrice"`
		MaxFeePerGas         *math.HexOrDecimal256 `json:"maxFeePerGas,omitempty"`
		MaxPriorityFeePerGas *math.HexOrDecimal256 `json:"maxPriorityFeePerGas,omitempty"`
		Nonce                *math.HexOrDecimal64  `json:"nonce"`
		To                   *string               `json:"to"`
		Data                 []string              `json:"data"`
		AccessLists          []*types.AccessList   `json:"accessLists,omitempty"`
		GasLimit             []math.HexOrDecimal64 `json:"gasLimit"`
		Value                []string              `json:"value"`
		PrivateKey           *hexutil.Bytes        `json:"secretKey"`
		Sender               *common.Address       `json:"sender,omitempty"`
		BlobVersionedHashes  []common.Hash         `json:"blobVersionedHashes,omitempty"`
		BlobGasFeeCap        *math.HexOrDecimal256 `json:"maxFeePerBlobGas,omitempty"`
	}
	var dec stTransaction
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.GasPrice != nil {
		s.GasPrice = (*big.Int)(dec.GasPrice)
	}
	if dec.MaxFeePerGas != nil {
		s.MaxFeePerGas = (*big.Int)(dec.MaxFeePerGas)
	}
	if dec.MaxPriorityFeePerGas != nil {
		s.MaxPriorityFeePerGas = (*big.Int)(dec.MaxPriorityFeePerGas)
	}
	if dec.Nonce != nil {
		s.Nonce = uint64(*dec.Nonce)
	}
	if dec.To != nil {
		s.To = *dec.To
	}
	if dec.Data != nil {
		s.Data = dec.Data
	}
	if dec.AccessLists != nil {
		s.AccessLists = dec.AccessLists
	}
	if dec.GasLimit != nil {
		s.GasLimit = make([]uint64, len(dec.GasLimit))
		for k, v := range dec.GasLimit {
			s.GasLimit[k] = uint64(v)
		}
	}
	if dec.Value != nil {
		s.Value = dec.Value
	}
	if dec.PrivateKey != nil {
		s.PrivateKey = *dec.PrivateKey
	}
	if dec.Sender != nil {
		s.Sender = *dec.Sender
	if dec.BlobVersionedHashes != nil {
		s.BlobVersionedHashes = dec.BlobVersionedHashes
	}
	if dec.BlobGasFeeCap != nil {
		s.BlobGasFeeCap = (*big.Int)(dec.BlobGasFeeCap)
	}
	return nil
}
