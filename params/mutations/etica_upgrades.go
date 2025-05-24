// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package mutations

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params/types/ctypes"
	"github.com/ethereum/go-ethereum/params/vars"
)

var (

	// ErrBadProEticav2Extra is returned if a header doesn't support the Eticav2 fork on a
	// pro-fork client.
	ErrBadProEticav2Extra = errors.New("bad Eticav2 pro-fork extra-data")

	// ErrBadNoEticav2Extra is returned if a header does support the Eticav2 fork on a no-
	// fork client.
	ErrBadNoEticav2Extra = errors.New("bad Eticav2 no-fork extra-data")

	// ErrBadProEticav3Extra is returned if a header doesn't support the Eticav3 fork on a
	// pro-fork client.
	ErrBadProEticav3Extra = errors.New("bad Eticav3 pro-fork extra-data")

	// ErrBadNoEticav3Extra is returned if a header does support the Eticav3 fork on a no-
	// fork client.
	ErrBadNoEticav3Extra = errors.New("bad Eticav3 no-fork extra-data")

	// ErrBadProEticav4Extra is returned if a header doesn't support the Eticav4 fork on a
	// pro-fork client.
	ErrBadProEticav4Extra = errors.New("bad Eticav4 pro-fork extra-data")

	// ErrBadNoEticav4Extra is returned if a header does support the Eticav4 fork on a no-
	// fork client.
	ErrBadNoEticav4Extra = errors.New("bad Eticav4 no-fork extra-data")

	// ErrBadProEticav5Extra is returned if a header doesn't support the Eticav5 fork on a
	// pro-fork client.
	ErrBadProEticav5Extra = errors.New("bad Eticav5 pro-fork extra-data")

	// ErrBadNoEticav5Extra is returned if a header does support the Eticav5 fork on a no-
	// fork client.
	ErrBadNoEticav5Extra = errors.New("bad Eticav5 no-fork extra-data")

	// ErrBadProEticav6Extra is returned if a header doesn't support the Eticav6 fork on a
	// pro-fork client.
	ErrBadProEticav6Extra = errors.New("bad Eticav6 pro-fork extra-data")

	// ErrBadNoEticav6Extra is returned if a header does support the Eticav6 fork on a no-
	// fork client.
	ErrBadNoEticav6Extra = errors.New("bad Eticav6 no-fork extra-data")
)

// VerifyEticav2HeaderExtraData validates the extra-data field of a block header to
// ensure it conforms to Eticav2 hard-fork rules.
//
// Eticav2 hard-fork extension to the header validity:
//
//   - if the node is no-fork, do not accept blocks in the [fork, fork+10) range
//     with the fork specific extra-data set.
//   - if the node is pro-fork, require blocks in the specific range to have the
//     unique extra-data set.
func VerifyEticav2HeaderExtraData(config ctypes.ChainConfigurator, header *types.Header) error {
	// If the config wants the Eticav2 fork, it should validate the extra data.
	Eticav2ForkBlock := config.GetEticaSmartContractv2Transition()
	if Eticav2ForkBlock == nil {
		return nil
	}
	Eticav2ForkBlockB := new(big.Int).SetUint64(*Eticav2ForkBlock)
	// Make sure the block is within the fork's modified extra-data range
	limit := new(big.Int).Add(Eticav2ForkBlockB, vars.Eticav2ForkExtraRange)
	if header.Number.Cmp(Eticav2ForkBlockB) < 0 || header.Number.Cmp(limit) >= 0 {
		return nil
	}
	if !bytes.Equal(header.Extra, vars.Eticav2ForkBlockExtra) {
		return ErrBadProEticav2Extra
	}
	return nil
}

// (Meticulous, Etica Hardfork 1). Update Etica Smart Contract bytecode to v2
func ApplyEticav2(statedb *state.StateDB) {
	// Apply Etica Smart Contract v2
	eticav2code := statedb.GetCode(vars.EticaSmartContractAddressv2)
	statedb.SetCode(vars.EticaSmartContractAddress, eticav2code)
	statedb.SetNonce(vars.EticaSmartContractAddress, statedb.GetNonce(vars.EticaSmartContractAddress)+1)
}

// (Meticulous, Etica Hardfork 1). Update Etica Smart Contract bytecode to v2
func ApplyCruciblev2(statedb *state.StateDB) {
	// Apply Etica Smart Contract v2
	cruciblev2code := statedb.GetCode(vars.CrucibleSmartContractAddressv2)
	statedb.SetCode(vars.CrucibleSmartContractAddress, cruciblev2code)
	statedb.SetNonce(vars.CrucibleSmartContractAddress, statedb.GetNonce(vars.CrucibleSmartContractAddress)+1)
}

// VerifyEticav3HeaderExtraData validates the extra-data field of a block header to
// ensure it conforms to Eticav3 hard-fork rules.
//
// Eticav3 hard-fork extension to the header validity:
//
//   - if the node is no-fork, do not accept blocks in the [fork, fork+10) range
//     with the fork specific extra-data set.
//   - if the node is pro-fork, require blocks in the specific range to have the
//     unique extra-data set.
func VerifyEticav3HeaderExtraData(config ctypes.ChainConfigurator, header *types.Header) error {
	// If the config wants the Eticav3 fork, it should validate the extra data.
	Eticav3ForkBlock := config.GetEticaSmartContractv3Transition()
	if Eticav3ForkBlock == nil {
		return nil
	}
	Eticav3ForkBlockB := new(big.Int).SetUint64(*Eticav3ForkBlock)
	// Make sure the block is within the fork's modified extra-data range
	limit := new(big.Int).Add(Eticav3ForkBlockB, vars.Eticav3ForkExtraRange)
	if header.Number.Cmp(Eticav3ForkBlockB) < 0 || header.Number.Cmp(limit) >= 0 {
		return nil
	}
	if !bytes.Equal(header.Extra, vars.Eticav3ForkBlockExtra) {
		return ErrBadProEticav3Extra
	}
	return nil
}

// (Guardian, Etica Hardfork 2). Update Etica Smart Contract bytecode to v3
func ApplyEticav3(statedb *state.StateDB) {
	// Apply Etica Smart Contract v3
	eticav3code := statedb.GetCode(vars.EticaSmartContractAddressv3)
	statedb.SetCode(vars.EticaSmartContractAddress, eticav3code)
	statedb.SetNonce(vars.EticaSmartContractAddress, statedb.GetNonce(vars.EticaSmartContractAddress)+1)
}

// (Guardian, Etica Hardfork 1). Update Etica Smart Contract bytecode to v3
func ApplyCruciblev3(statedb *state.StateDB) {
	// Apply Etica Smart Contract v3
	fmt.Printf("*-*-*-*-**-*-*-*-*-*- ApplyCruciblev3 *-*-*-*-*-**-*-*-*-*-*-*-*-*-")
	cruciblev3code := statedb.GetCode(vars.CrucibleSmartContractAddressv3)
	statedb.SetCode(vars.CrucibleSmartContractAddress, cruciblev3code)
	statedb.SetNonce(vars.CrucibleSmartContractAddress, statedb.GetNonce(vars.CrucibleSmartContractAddress)+1)
}

// VerifyEticav4HeaderExtraData validates the extra-data field of a block header to
// ensure it conforms to Eticav4 hard-fork rules.
//
// Eticav4 hard-fork extension to the header validity:
//
//   - if the node is no-fork, do not accept blocks in the [fork, fork+10) range
//     with the fork specific extra-data set.
//   - if the node is pro-fork, require blocks in the specific range to have the
//     unique extra-data set.
func VerifyEticav4HeaderExtraData(config ctypes.ChainConfigurator, header *types.Header) error {
	// If the config wants the Eticav4 fork, it should validate the extra data.
	Eticav4ForkBlock := config.GetEticaSubset1Transition()
	if Eticav4ForkBlock == nil {
		return nil
	}
	Eticav4ForkBlockB := new(big.Int).SetUint64(*Eticav4ForkBlock)
	// Make sure the block is within the fork's modified extra-data range
	limit := new(big.Int).Add(Eticav4ForkBlockB, vars.Eticav4ForkExtraRange)
	if header.Number.Cmp(Eticav4ForkBlockB) < 0 || header.Number.Cmp(limit) >= 0 {
		return nil
	}
	if !bytes.Equal(header.Extra, vars.Eticav4ForkBlockExtra) {
		return ErrBadProEticav4Extra
	}
	return nil
}

// (Pursuance, Etica Hardfork 3). Update Etica Smart Contract bytecode to v4
func ApplyEticav4(statedb *state.StateDB) {
	// Apply Etica Smart Contract v4
	eticav4code := statedb.GetCode(vars.EticaSmartContractAddressv4)
	statedb.SetCode(vars.EticaSmartContractAddress, eticav4code)
	statedb.SetNonce(vars.EticaSmartContractAddress, statedb.GetNonce(vars.EticaSmartContractAddress)+1)
}

// (Pursuance, Etica Hardfork 3). Update Etica Smart Contract bytecode to v4
func ApplyCruciblev4(statedb *state.StateDB) {
	// Apply Etica Smart Contract v4
	fmt.Printf("*-*-*-*-**-*-*-*-*-*- ApplyCruciblev4 *-*-*-*-*-**-*-*-*-*-*-*-*-*-")
	cruciblev4code := statedb.GetCode(vars.CrucibleSmartContractAddressv4)
	statedb.SetCode(vars.CrucibleSmartContractAddress, cruciblev4code)
	statedb.SetNonce(vars.CrucibleSmartContractAddress, statedb.GetNonce(vars.CrucibleSmartContractAddress)+1)
}

// VerifyEticav5HeaderExtraData validates the extra-data field of a block header to
// ensure it conforms to Eticav5 hard-fork rules.
//
// Eticav5 hard-fork extension to the header validity:
//
//   - if the node is no-fork, do not accept blocks in the [fork, fork+10) range
//     with the fork specific extra-data set.
//   - if the node is pro-fork, require blocks in the specific range to have the
//     unique extra-data set.
func VerifyEticav5HeaderExtraData(config ctypes.ChainConfigurator, header *types.Header) error {
	// If the config wants the Eticav5 fork, it should validate the extra data.
	Eticav5ForkBlock := config.GetEticaSmartContractv5Transition()
	if Eticav5ForkBlock == nil {
		return nil
	}
	Eticav5ForkBlockB := new(big.Int).SetUint64(*Eticav5ForkBlock)
	// Make sure the block is within the fork's modified extra-data range
	limit := new(big.Int).Add(Eticav5ForkBlockB, vars.Eticav5ForkExtraRange)
	if header.Number.Cmp(Eticav5ForkBlockB) < 0 || header.Number.Cmp(limit) >= 0 {
		return nil
	}
	if !bytes.Equal(header.Extra, vars.Eticav5ForkBlockExtra) {
		return ErrBadProEticav5Extra
	}
	return nil
}

// (Aegis Etica Hardfork). Update Etica Smart Contract bytecode to v5
func ApplyEticav5(statedb *state.StateDB) {
	// Apply Etica Smart Contract v5
	eticav5code := statedb.GetCode(vars.EticaSmartContractAddressv5)
	statedb.SetCode(vars.EticaSmartContractAddress, eticav5code)
	statedb.SetNonce(vars.EticaSmartContractAddress, statedb.GetNonce(vars.EticaSmartContractAddress)+1)
}

// (Aegis Etica Hardfork). Update Etica Smart Contract bytecode to v5
func ApplyCruciblev5(statedb *state.StateDB) {
	// Apply Etica Smart Contract v5
	fmt.Printf("*-*-*-*-**-*-*-*-*-*- ApplyCruciblev5 *-*-*-*-*-**-*-*-*-*-*-*-*-*-")
	cruciblev5code := statedb.GetCode(vars.CrucibleSmartContractAddressv5)
	statedb.SetCode(vars.CrucibleSmartContractAddress, cruciblev5code)
	statedb.SetNonce(vars.CrucibleSmartContractAddress, statedb.GetNonce(vars.CrucibleSmartContractAddress)+1)
}

// VerifyEticav6HeaderExtraData validates the extra-data field of a block header to
// ensure it conforms to Eticav6 hard-fork rules.
//
// Eticav6 hard-fork extension to the header validity:
//
//   - if the node is no-fork, do not accept blocks in the [fork, fork+10) range
//     with the fork specific extra-data set.
//   - if the node is pro-fork, require blocks in the specific range to have the
//     unique extra-data set.
func VerifyEticav6HeaderExtraData(config ctypes.ChainConfigurator, header *types.Header) error {
	// If the config wants the Eticav6 fork, it should validate the extra data.
	Eticav6ForkBlock := config.GetEticaSmartContractv6Transition()
	if Eticav6ForkBlock == nil {
		return nil
	}
	Eticav6ForkBlockB := new(big.Int).SetUint64(*Eticav6ForkBlock)
	// Make sure the block is within the fork's modified extra-data range
	limit := new(big.Int).Add(Eticav6ForkBlockB, vars.Eticav6ForkExtraRange)
	if header.Number.Cmp(Eticav6ForkBlockB) < 0 || header.Number.Cmp(limit) >= 0 {
		return nil
	}
	if !bytes.Equal(header.Extra, vars.Eticav6ForkBlockExtra) {
		return ErrBadProEticav6Extra
	}
	return nil
}

// (Themis Etica Hardfork). Update Etica Smart Contract bytecode to v6
func ApplyEticav6(statedb *state.StateDB) {
	// Apply Etica Smart Contract v6
	eticav6code := statedb.GetCode(vars.EticaSmartContractAddressv6)
	statedb.SetCode(vars.EticaSmartContractAddress, eticav6code)
	statedb.SetNonce(vars.EticaSmartContractAddress, statedb.GetNonce(vars.EticaSmartContractAddress)+1)
}

// (Themis Etica Hardfork). Update Etica Smart Contract bytecode to v6
func ApplyCruciblev6(statedb *state.StateDB) {
	// Apply Etica Smart Contract v6
	fmt.Printf("*-*-*-*-**-*-*-*-*-*- ApplyCruciblev6 *-*-*-*-*-**-*-*-*-*-*-*-*-*-")
	cruciblev6code := statedb.GetCode(vars.CrucibleSmartContractAddressv6)
	statedb.SetCode(vars.CrucibleSmartContractAddress, cruciblev6code)
	statedb.SetNonce(vars.CrucibleSmartContractAddress, statedb.GetNonce(vars.CrucibleSmartContractAddress)+1)
}
