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

package vars

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// Etica Mainnet Smart Contract //
var EticaSmartContractAddress = common.HexToAddress("0x34c61EA91bAcdA647269d4e310A86b875c09946f") // Etica Mainnet Smart Contract Warning: dont forget to set it back to 0x34c61EA91bAcdA647269d4e310A86b875c09946f after tests
// Crucible Testnet Smart Contract //
var CrucibleSmartContractAddress = common.HexToAddress("0x558593Bc92E6F242a604c615d93902fc98efcA82") // Crucible address: 0x558593Bc92E6F242a604c615d93902fc98efcA82

// --------- Eticav2 (smart contract hardfork 1) ----------- //

// --------- main smart contract loads bytecode from following contract ----------- //
var EticaSmartContractAddressv2 = common.HexToAddress("0x64cB3Bc8cF8324432838B5c58519F782482C9861") // Etica v2, Meticulous Hardfork
var CrucibleSmartContractAddressv2 = common.HexToAddress("0x3cA0Dc9373F33993Ec25643B92759ce637C8400f")

// Eticav2ForkBlockExtra is the block header extra-data field to set for the Eticav2 fork
// point and a number of consecutive blocks to allow fast/light syncers to correctly
// pick the side they want.  0x657469636176322d686172642d666f726b is hex representation of "eticav2-hard-fork".
var Eticav2ForkBlockExtra = common.FromHex("0x657469636176322d686172642d666f726b")

// Eticav2ForkExtraRange is the number of consecutive blocks from the Eticav2 fork point
// to override the extra-data in to prevent no-fork attacks.
var Eticav2ForkExtraRange = big.NewInt(10)

// --------- Eticav2 (smart contract hardfork 1) ----------- //

// --------- Eticav3 (Etica smart contract hardfork 2) ----------- //

// --------- main smart contract loads bytecode from following contract ----------- //
var EticaSmartContractAddressv3 = common.HexToAddress("0xD0fFdAf3C0edb303Bb1Fe1a79a8153DA5c7AaABC")    // Etica v3, Guardian Hardfork
var CrucibleSmartContractAddressv3 = common.HexToAddress("0x76DC8590514086b11c444959D7DeA96A7A71892d") // Etica v3, Guardian Hardfork

// Eticav3ForkBlockExtra is the block header extra-data field to set for the Eticav3 fork
// point and a number of consecutive blocks to allow fast/light syncers to correctly
// pick the side they want.  0x677561726469616e2d686172642d666f726b is hex representation of "guardian-hard-fork".
var Eticav3ForkBlockExtra = common.FromHex("0x677561726469616e2d686172642d666f726b")

// Eticav3ForkExtraRange is the number of consecutive blocks from the Eticav3 fork point
// to override the extra-data in to prevent no-fork attacks.
var Eticav3ForkExtraRange = big.NewInt(10)

// --------- Eticav3 (Etica smart contract hardfork 2) ----------- //

// --------- Eticav4 (Blacklisted addresses) ----------- //
// BlacklistedAddresses due to the Xeggex exchange exploit
var BlacklistedAddressesSubset1 = map[common.Address]bool{
	common.HexToAddress("0x5CcCcb6d334197c7C4ba94E7873d0ef11381CD4e"): true,
}

var EticaSmartContractAddressv4 = common.HexToAddress("0xFa49C16EbebBd0B2C3Bb4Ef4897B7399D061bf8f")    // Etica v4, Pursuance Hardfork
var CrucibleSmartContractAddressv4 = common.HexToAddress("0xa037fb5d328Aa8B0C01bA9DFc18D63164DEDDb51") // Etica v4, Pursuance Hardfork

// Eticav4ForkBlockExtra is the block header extra-data field to set for the Eticav4 fork
// point and a number of consecutive blocks to allow fast/light syncers to correctly
// pick the side they want.  0x7075727375616e63652d686172642d666f726b is hex representation of "pursuance-hard-fork".
var Eticav4ForkBlockExtra = common.FromHex("0x7075727375616e63652d686172642d666f726b")

// Eticav4ForkExtraRange is the number of consecutive blocks from the Eticav4 fork point
// to override the extra-data in to prevent no-fork attacks.
var Eticav4ForkExtraRange = big.NewInt(10)

// --------- Eticav4 (Blacklisted addresses) ----------- //

// --------- Eticav5 (Etica smart contract hardfork 4) ----------- //

// --------- main smart contract loads bytecode from following contract ----------- //
var EticaSmartContractAddressv5 = common.HexToAddress("0xc537E70E225EB99bC9ec36fEfB214105B23E47A8")    // Etica v5, Aegis Hardfork
var CrucibleSmartContractAddressv5 = common.HexToAddress("0xA0f8507483bd6e9282360C938c014035E0f79Cf4") // Etica v5, Aegis Hardfork

// Eticav5ForkBlockExtra is the block header extra-data field to set for the Eticav5 fork
// point and a number of consecutive blocks to allow fast/light syncers to correctly
// pick the side they want.  0x61656769732d686172642d666f726b is hex representation of "aegis-hard-fork".
var Eticav5ForkBlockExtra = common.FromHex("0x61656769732d686172642d666f726b")

// Eticav5ForkExtraRange is the number of consecutive blocks from the Eticav5 fork point
// to override the extra-data in to prevent no-fork attacks.
var Eticav5ForkExtraRange = big.NewInt(10)

// --------- Eticav5 (Etica smart contract hardfork ) ----------- //

// --------- Eticav6 (Etica smart contract hardfork 5) ----------- //

// BlacklistedAddresses due to the Xeggex exchange exploit
var BlacklistedAddressesSubset2 = map[common.Address]bool{
	common.HexToAddress("0x5CcCcb6d334197c7C4ba94E7873d0ef11381CD4e"): true,
}

// --------- main smart contract loads bytecode from following contract ----------- //
var EticaSmartContractAddressv6 = common.HexToAddress("0xc537E70E225EB99bC9ec36fEfB214105B23E47A8")    // Etica v6, Themis Hardfork
var CrucibleSmartContractAddressv6 = common.HexToAddress("0xA0f8507483bd6e9282360C938c014035E0f79Cf4") // Etica v6, Themis Hardfork

// Eticav6ForkBlockExtra is the block header extra-data field to set for the Eticav6 fork
// point and a number of consecutive blocks to allow fast/light syncers to correctly
// pick the side they want.  0x7468656d69732d686172642d666f726b is hex representation of "themis-hard-fork".
var Eticav6ForkBlockExtra = common.FromHex("0x7468656d69732d686172642d666f726b")

// Eticav6ForkExtraRange is the number of consecutive blocks from the Eticav6 fork point
// to override the extra-data in to prevent no-fork attacks.
var Eticav6ForkExtraRange = big.NewInt(10)

// --------- Eticav6 (Etica smart contract hardfork ) ----------- //
