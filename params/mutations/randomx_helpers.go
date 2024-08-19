package mutations

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params/vars"
)

const nonceOffset = 39
const reservedExtranonceSize = 8 // 8 bytes reservedExtranonce (guaranties uniqueness and prevent collisions, each miner mines with a specific blob)
const reservedOffset = 55

func CalculateDigest(challengeNumber string, sender common.Address, nonce *big.Int) [32]byte {
	// Convert challengeNumber to bytes
	challengeBytes := []byte(challengeNumber)

	// Convert sender address to bytes
	senderBytes := sender.Bytes()

	// Convert nonce to bytes
	nonceBytes := nonce.Bytes()

	// Concatenate all bytes (this is equivalent to abi.encodePacked in Solidity)
	packed := append(challengeBytes, senderBytes...)
	packed = append(packed, nonceBytes...)

	// Calculate keccak256 hash
	hash := crypto.Keccak256(packed)

	// Convert to [32]byte
	var digest [32]byte
	copy(digest[:], hash)

	return digest
}

func VerifyEticaTransaction(tx *types.Transaction, statedb *state.StateDB) error {
	fmt.Printf("*-*-*-*-**-*-*-*-*-*-Verifying Etica transaction *-*-*-*-*-**-*-*-*-*-*-*-*-*-")
	fmt.Printf("Verifying Etica transaction: %s\n", tx.Hash().Hex())
	txData := tx.Data()
	txDataHex := hex.EncodeToString(txData)
	fmt.Printf("Verifying Etica transaction data (hex): 0x%s\n", txDataHex)
	fmt.Printf("Verifying Etica transaction data (raw): %v\n", txData)

	fmt.Printf("EticaSmartContractAddress: %s\n", vars.EticaSmartContractAddress)
	if tx.To() == nil || *tx.To() != vars.EticaSmartContractAddress {
		fmt.Println("Transaction is not to Etica smart contract")
		return nil
	} else {
		fmt.Println("Transaction is to Etica smart contract")
	}

	// Check if the transaction is calling the mintrandomX() function
	if !IsSolutionProposal(tx.Data()) {
		fmt.Println("Transaction is not a mintrandomX call")
		return nil
	}

	fmt.Println("Transaction is to Etica smart contract")

	// Initialize RandomX (you might want to do this once and reuse it)
	cache := InitRandomX(FlagDefault)
	if cache == nil {
		return fmt.Errorf("failed to initialize RandomX cache")
	}
	defer DestroyRandomX(cache)

	vm := CreateVM(cache, FlagDefault)
	if vm == nil {
		return fmt.Errorf("failed to create RandomX")
	}
	defer DestroyVM(vm)

	nonce, blockHeader, currentChallenge, randomxHash, claimedTarget, seedHash, extraNonce, err := ExtractSolutionData(tx.Data())
	if err != nil {
		if err.Error() == "Invalid function selector" {
			fmt.Println("Failed to Extract Solution Data, Invalid function selector")
			return nil // Not an error, just not the transaction we're looking for
		}
		fmt.Printf("Error extracting solution data: %v\n", err)
		return err
	}

	fmt.Println("Transaction is a mintrandomX call")
	fmt.Printf("Extracted block header: %x\n", blockHeader)
	fmt.Printf("Extracted nonce: %x\n", nonce)
	fmt.Printf("Extracted ExtraNonce: %x\n", nonce)
	fmt.Printf("Extracted claimedTarget: %s\n", claimedTarget.String())

	fmt.Printf("SeedHash: %v\n", seedHash)
	fmt.Printf("currentChallenge: %v\n", currentChallenge)

	blockHeight := uint64(3182000) // WARNING: use hardcoded value for tests need to implement get it from tx inputs

	fmt.Println(" ****** Performing RandomX verification... ********")
	fmt.Printf("randomxHash: %v\n", randomxHash)

	// Create a copy of the block header and insert the nonce at the correct offset
	blobWithNonce := make([]byte, len(blockHeader))
	copy(blobWithNonce, blockHeader)
	copy(blobWithNonce[nonceOffset:], nonce[:])

	// Get the sender's address
	from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
	if err != nil {
		return fmt.Errorf("failed to get transaction sender: %v", err)
	}

	fmt.Printf("Miner from: %x\n", from)

	extraNonceHash := crypto.Keccak256Hash(
		from.Bytes(),
		common.LeftPadBytes(extraNonce[:], 8),
		common.LeftPadBytes(currentChallenge[:], 32),
	)

	fmt.Printf("*-*-**-*-**-*-**-*-**-*-*-*- extraNonceHash *-**-*-*-*-*-**-*-*-*-*-* : %s\n", extraNonceHash.Hex())

	// Step 3: Truncate extraNonceHash to extraNonceSize
	truncatedExtraNonceHash := extraNonceHash[:8]

	fmt.Printf("*-*-**-*-**-*-**-*-**-*-*-*- truncatedExtraNonceHash *-**-*-*-*-*-**-*-*-*-*-* : %x\n", truncatedExtraNonceHash)

	fmt.Printf("blobWithNonce BEFORE insert truncatedExtraNonceHash:   %x\n", blobWithNonce)

	// Step 4: Insert the truncated extraNonceHash at reservedOffset (55 bytes)
	copy(blobWithNonce[reservedOffset:], truncatedExtraNonceHash)

	fmt.Printf("blobWithNonce AFTER insert truncatedExtraNonceHash:   %x\n", blobWithNonce)

	// valid, err := CheckSolution(vm, blockHeader, nonce, correctSolution, difficulty) -- > replaced by next line:
	valid, err := CheckRandomxSolution(vm, blobWithNonce, randomxHash, claimedTarget, blockHeight, seedHash)

	if err != nil {
		fmt.Printf("RandomX verification error: %v\n", err)
		return err
	}
	if valid {
		fmt.Println("RandomX verification passed")

		// Update the RandomX state
		updateRandomXState(statedb, currentChallenge, nonce, from, randomxHash, claimedTarget, seedHash)
		// return something here to main process for success message

	} else {
		fmt.Println("RandomX verification failed")
		return fmt.Errorf("invalid RandomX solution")
	}

	return nil
}

func IsSolutionProposal(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	functionSelector := data[:4]
	fmt.Printf("Function selector: %s\n", hex.EncodeToString(functionSelector))
	// Replace with actual selector for mintrandomX
	expectedSelector := []byte{0x03, 0x7d, 0x2f, 0x35} // Actual selector for mintrandomX f0a9b55b
	return bytes.Equal(functionSelector, expectedSelector)
}

func ExtractSolutionData(data []byte) (nonce [4]byte, blockHeader []byte, currentChallenge [32]byte, randomxHash []byte, claimedTarget *big.Int, seedHash []byte, extraNonce [8]byte, err error) {
	// Check if the data is long enough to contain all required fields
	// 4 (selector) + 32 (nonce) + 80 (blockHeader) + 32 (currentChallenge) + 32 (randomxHash) + 32 (claimedTarget) + 32 (seedHash) + 8 (extraNonce) = 252 bytes
	if len(data) < 252 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short to contain solution data")
	}

	// The first 4 bytes are the function selector, which we can check
	functionSelector := data[:4]
	expectedSelector := []byte{0x03, 0x7d, 0x2f, 0x35} // Need to Replace with actual selector for mintrandomX
	if !bytes.Equal(functionSelector, expectedSelector) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Invalid function selector")
	}

	// Extract nonce (4 bytes)
	copy(nonce[:], data[4:8])
	fmt.Printf("Extracted nonce: %x (hex) \n", nonce)

	// Extract blockHeader offset
	blockHeaderOffset := new(big.Int).SetBytes(data[36:68]).Uint64()

	// Extract currentChallenge (bytes32)
	copy(currentChallenge[:], data[68:100])
	fmt.Printf("Extracted currentChallenge: %x\n", currentChallenge)

	// Extract randomxHash offset
	randomxHashOffset := new(big.Int).SetBytes(data[100:132]).Uint64()

	// Extract claimedTarget (uint256)
	claimedTarget = new(big.Int).SetBytes(data[132:164])
	fmt.Printf("Extracted claimedTarget: %d\n", claimedTarget)

	// Extract seedHash offset
	seedHashOffset := new(big.Int).SetBytes(data[164:196]).Uint64()

	// Extract extraNonce (8 bytes)
	copy(extraNonce[:], data[196:204])
	fmt.Printf("Extracted extraNonce: %x (hex) \n", extraNonce)

	// Extract blockHeader (dynamic bytes)
	blockHeaderStart := 4 + blockHeaderOffset
	blockHeaderLength := new(big.Int).SetBytes(data[blockHeaderStart : blockHeaderStart+32]).Uint64()
	blockHeaderStart += 32
	blockHeaderEnd := blockHeaderStart + blockHeaderLength
	if blockHeaderEnd > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Invalid blockHeader length")
	}
	blockHeader = make([]byte, blockHeaderLength)
	copy(blockHeader, data[blockHeaderStart:blockHeaderEnd])
	fmt.Printf("Extracted blockHeader (length %d): %x\n", blockHeaderLength, blockHeader)

	// Extract randomxHash (dynamic bytes)
	randomxHashStart := 4 + randomxHashOffset
	randomxHashLength := new(big.Int).SetBytes(data[randomxHashStart : randomxHashStart+32]).Uint64()
	randomxHashStart += 32
	randomxHashEnd := randomxHashStart + randomxHashLength
	if randomxHashEnd > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Invalid randomxHash length")
	}
	randomxHash = make([]byte, randomxHashLength)
	copy(randomxHash, data[randomxHashStart:randomxHashEnd])
	fmt.Printf("Extracted randomxHash (length %d): %x\n", randomxHashLength, randomxHash)

	// Extract seedHash (dynamic bytes)
	seedHashStart := 4 + seedHashOffset
	seedHashLength := new(big.Int).SetBytes(data[seedHashStart : seedHashStart+32]).Uint64()
	seedHashStart += 32
	seedHashEnd := seedHashStart + seedHashLength
	if seedHashEnd > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Invalid seedHash length")
	}
	seedHash = make([]byte, seedHashLength)
	copy(seedHash, data[seedHashStart:seedHashEnd])
	fmt.Printf("Extracted seedHash (length %d): %x\n", seedHashLength, seedHash)

	return nonce, blockHeader, currentChallenge, randomxHash, claimedTarget, seedHash, extraNonce, nil
}

/*

func ExtractSolutionData(data []byte) (nonce []byte, blockHeader []byte, currentChallenge [32]byte, randomxHash []byte, claimedTarget *big.Int, seedHash []byte, err error) {
	// Check if the data is long enough to contain all required fields
	// 4 (selector) + 32 (nonce) + 80 (blockHeader) + 32 (currentChallenge) + 32 (randomxHash) + 32 (claimedTarget) + 32 (seedHash) = 244 bytes
	if len(data) < 244 {
		return nil, nil, [32]byte{}, nil, nil, nil, errors.New("Data too short to contain solution data")
	}

	// The first 4 bytes are the function selector, which we can check
	functionSelector := data[:4]
	expectedSelector := []byte{0x28, 0x9d, 0x1d, 0x41} // Need to Replace with actual selector for mintrandomX
	if !bytes.Equal(functionSelector, expectedSelector) {
		return nil, nil, [32]byte{}, nil, nil, nil, errors.New("Invalid function selector")
	}

	// Extract nonce (uint256)
	nonce = make([]byte, 32)
	copy(nonce, data[4:36])
	// Remove leading zeros from nonce
	nonce = bytes.TrimLeft(nonce, "\x00")
	fmt.Printf("Extracted nonce: %x (hex) / %d (decimal)\n", nonce, new(big.Int).SetBytes(nonce))

	// Extract blockHeader (80 bytes)
	blockHeader = make([]byte, 80)
	copy(blockHeader, data[36:116])

	// Extract currentChallenge (bytes32)
	copy(currentChallenge[:], data[68:100])
	fmt.Printf("Extracted currentChallenge: %x\n", currentChallenge)

	// Extract randomxHash (bytes32)
	copy(randomxHash[:], data[100:132])
	fmt.Printf("Extracted randomxHash: %x\n", randomxHash)

	// Extract difficulty (uint256)
	claimedTarget = new(big.Int).SetBytes(data[100:132])
	fmt.Printf("Extracted difficulty: %d\n", claimedTarget)

	// Extract blockHeader (dynamic bytes)
	blockHeaderOffset := new(big.Int).SetBytes(data[36:68]).Uint64()
	blockHeaderStart := 4 + blockHeaderOffset
	blockHeaderLength := new(big.Int).SetBytes(data[blockHeaderStart : blockHeaderStart+32]).Uint64()
	blockHeaderStart += 32
	blockHeaderEnd := blockHeaderStart + blockHeaderLength
	if blockHeaderEnd > uint64(len(data)) {
		return nil, nil, [32]byte{}, nil, nil, nil, errors.New("Invalid blockHeader length")
	}
	blockHeader = make([]byte, blockHeaderLength)
	copy(blockHeader, data[blockHeaderStart:blockHeaderEnd])
	fmt.Printf("Extracted blockHeader (length %d): %x\n", blockHeaderLength, blockHeader)

	// Extract randomxHash (dynamic bytes)
	randomxHashOffset := new(big.Int).SetBytes(data[100:132]).Uint64()
	randomxHashStart := 4 + randomxHashOffset
	randomxHashLength := new(big.Int).SetBytes(data[randomxHashStart : randomxHashStart+32]).Uint64()
	randomxHashStart += 32
	randomxHashEnd := randomxHashStart + randomxHashLength
	if randomxHashEnd > uint64(len(data)) {
		return nil, nil, [32]byte{}, nil, nil, nil, errors.New("Invalid randomxHash length")
	}
	randomxHash = make([]byte, randomxHashLength)
	copy(randomxHash, data[randomxHashStart:randomxHashEnd])
	fmt.Printf("Extracted randomxHash (length %d): %x\n", randomxHashLength, randomxHash)

	// Extract seedHash (dynamic bytes)
	seedHashOffset := new(big.Int).SetBytes(data[132:164]).Uint64()
	seedHashStart := 4 + seedHashOffset
	seedHashLength := new(big.Int).SetBytes(data[seedHashStart : seedHashStart+32]).Uint64()
	seedHashStart += 32
	seedHashEnd := seedHashStart + seedHashLength
	if seedHashEnd > uint64(len(data)) {
		return nil, nil, [32]byte{}, nil, nil, nil, errors.New("Invalid seedHash length")
	}
	seedHash = make([]byte, seedHashLength)
	copy(seedHash, data[seedHashStart:seedHashEnd])
	fmt.Printf("Extracted seedHash (length %d): %x\n", seedHashLength, seedHash)

	// Extract seedHash (bytes32)
	seedHash = make([]byte, 32)
	copy(seedHash, data[180:212])

	return nonce, blockHeader, currentChallenge, randomxHash, claimedTarget, seedHash, nil
}


*/

/*


Given these considerations, here's what we should do:

    Use a fixed-size array in Go:
    To more closely match Solidity's bytes32 and ensure consistent storage calculations, we should use a fixed-size array in Go. This will prevent any unexpected behavior due to varying lengths.
    Update our functions:
    We should modify our functions to use byte instead of []byte for the challengeNumber.

Here's how we can update our code:


*/

func calculateStorageSlot(challengeNumber [32]byte, minerAddress common.Address) common.Hash {
	// The slot of randomxSealSolutions is 70
	baseSlot := big.NewInt(70)

	// For the first level of mapping (challengeNumber)
	outerLocation := crypto.Keccak256Hash(
		challengeNumber[:],
		common.LeftPadBytes(baseSlot.Bytes(), 32),
	)

	// For the second level of mapping (minerAddress)
	finalSlot := crypto.Keccak256Hash(
		common.LeftPadBytes(minerAddress.Bytes(), 32),
		outerLocation.Bytes(),
	)

	return finalSlot
}

/*
func calculateStorageSlot(challengeNumber [32]byte, minerAddress common.Address) common.Hash {
	// The slot of randomxSealSolutions is 70
	baseSlot := big.NewInt(70)

	// Pad the baseSlot to 32 bytes
	paddedSlot := common.LeftPadBytes(baseSlot.Bytes(), 32)

	// Calculate the slot for the first level of mapping
	challengeNumberHash := crypto.Keccak256Hash(
		challengeNumber[:],
		paddedSlot,
	)

	// Calculate the slot for the second level of mapping
	finalSlot := crypto.Keccak256Hash(
		common.LeftPadBytes(minerAddress.Bytes(), 32),
		challengeNumberHash.Bytes(),
	)

	return finalSlot
} */

/*
func calculateStorageSlot(challengeNumber [32]byte, minerAddress common.Address) common.Hash {
	baseSlot := common.BigToHash(big.NewInt(70))
	challengeNumberHash := crypto.Keccak256Hash(
		challengeNumber[:],
		baseSlot.Bytes(),
	)
	finalSlot := crypto.Keccak256Hash(
		minerAddress.Bytes(),
		challengeNumberHash.Bytes(),
	)
	return finalSlot
} */

/*
func updateRandomXState(statedb *state.StateDB, challengeNumber [32]byte, solution [32]byte, miner common.Address, difficulty *big.Int) {
	solutionSlot := calculateStorageSlot(challengeNumber, miner)
	fmt.Printf("solutionSlot: %s\n", solutionSlot)
	existingSolution := statedb.GetState(vars.EticaSmartContractAddress, solutionSlot)
	fmt.Printf("existingSolution: %s\n", existingSolution)

	// Ensure nonce is 32 bytes
	paddedNonce := common.LeftPadBytes(solution[:], 32)

	// Combine nonce and difficulty similar to abi.encodePacked in Solidity
	combinedBytes := append(paddedNonce, common.LeftPadBytes(difficulty.Bytes(), 32)...)

	solutionHash := crypto.Keccak256Hash(combinedBytes)
	fmt.Printf("Solution Hash: %s\n", solutionHash.Hex())

	if existingSolution != (common.Hash{}) {
		fmt.Println("randomxSealSolutions already exists, not updating")
		return
	}

	statedb.SetState(vars.EticaSmartContractAddress, solutionSlot, solutionHash)

	fmt.Printf("Updated randomxSealSolutions:\n")
	challengeHex := "0x" + hex.EncodeToString(challengeNumber[:])
	fmt.Printf("Challenge Number: %s\n", challengeHex)
	fmt.Printf("Challenge Number: %x\n", challengeNumber)
	fmt.Printf("Miner Address: %s\n", miner.Hex())
	fmt.Printf("Solution Hash: %s\n", solutionHash.Hex())
} */

/*
func updateRandomXState(statedb *state.StateDB, challengeNumber [32]byte, nonce *big.Int, miner common.Address, randomxHash []byte, claimedTarget *big.Int, seedHash []byte) {
	solutionSlot := calculateStorageSlot(challengeNumber, miner)
	fmt.Printf("solutionSlot: %s\n", solutionSlot)
	existingSolution := statedb.GetState(vars.EticaSmartContractAddress, solutionSlot)
	fmt.Printf("existingSolution: %s\n", existingSolution)

	fmt.Printf("updateRandomXState nonce is: %s\n", nonce)

	fmt.Printf("updateRandomXState nonce is: %s\n", nonce)
	fmt.Printf("updateRandomXState claimedTarget is: %s\n", claimedTarget)

	// Pack nonce, claimedTarget, seedHash, and randomxHash
	packed := make([]byte, 32+32+len(seedHash)+len(randomxHash))
	nonce.FillBytes(packed[:32])
	claimedTarget.FillBytes(packed[32:64])
	copy(packed[64:64+len(seedHash)], seedHash)
	copy(packed[64+len(seedHash):], randomxHash)

	solutionSeal := crypto.Keccak256Hash(packed)
	fmt.Printf("Solution Seal: %s\n", solutionSeal.Hex())
	fmt.Printf("Seed Hash: %x\n", seedHash)
	fmt.Printf("Nonce: %s\n", nonce)
	fmt.Printf("claimedTarget: %s\n", claimedTarget)
	fmt.Printf("randomxHash: %x\n", randomxHash)

	if existingSolution != (common.Hash{}) {
		fmt.Println("randomxSealSolutions already exists, not updating")
		return
	}

	statedb.SetState(vars.EticaSmartContractAddress, solutionSlot, solutionSeal)

	fmt.Printf("Updated randomxSealSolutions:\n")
	challengeHex := "0x" + hex.EncodeToString(challengeNumber[:])
	fmt.Printf("Challenge Number: %s\n", challengeHex)
	fmt.Printf("Challenge Number: %x\n", challengeNumber)
	fmt.Printf("Miner Address: %s\n", miner.Hex())
	fmt.Printf("Nonce: 0x%x\n", nonce)
	fmt.Printf("claimedTarget: %s\n", claimedTarget.String())
	fmt.Printf("Packed bytes: 0x%x\n", packed) // Add this line to see the packed bytes
	fmt.Printf("Solution Seal: %s\n", solutionSeal.Hex())
} */

func updateRandomXState(statedb *state.StateDB, challengeNumber [32]byte, nonce [4]byte, miner common.Address, randomxHash []byte, claimedTarget *big.Int, seedHash []byte) {
	solutionSlot := calculateStorageSlot(challengeNumber, miner)
	fmt.Printf("solutionSlot: %s\n", solutionSlot)
	existingSolution := statedb.GetState(vars.EticaSmartContractAddress, solutionSlot)
	fmt.Printf("existingSolution: %s\n", existingSolution)

	if existingSolution != (common.Hash{}) {
		fmt.Println("randomxSealSolutions already exists, not updating")
		return
	}

	fmt.Printf("updateRandomXState nonce is: 0x%x\n", nonce)
	fmt.Printf("updateRandomXState claimedTarget is: %s\n", claimedTarget)
	fmt.Printf("updateRandomXState seedHash is: 0x%x\n", seedHash)
	fmt.Printf("updateRandomXState randomxHash is: 0x%x\n", randomxHash)

	// Pack nonce, claimedTarget, seedHash, and randomxHash
	packed := make([]byte, 4+32+len(seedHash)+len(randomxHash))
	copy(packed[:4], nonce[:])
	claimedTarget.FillBytes(packed[4:36])
	copy(packed[36:36+len(seedHash)], seedHash)
	copy(packed[36+len(seedHash):], randomxHash)

	// Log individual Keccak256 hashes
	fmt.Printf("Keccak256(nonce): %x\n", crypto.Keccak256(nonce[:]))
	fmt.Printf("Keccak256(claimedTarget): %x\n", crypto.Keccak256(claimedTarget.Bytes()))
	fmt.Printf("Keccak256(seedHash): %x\n", crypto.Keccak256(seedHash))
	fmt.Printf("Keccak256(randomxHash): %x\n", crypto.Keccak256(randomxHash))

	// Calculate Keccak256 hash
	solutionSeal := crypto.Keccak256Hash(packed)
	fmt.Printf("Solution Seal: %s\n", solutionSeal.Hex())
	fmt.Printf("Seed Hash: %x\n", seedHash)
	fmt.Printf("Nonce: %s\n", nonce)
	fmt.Printf("claimedTarget: %s\n", claimedTarget)
	fmt.Printf("randomxHash: %x\n", randomxHash)

	statedb.SetState(vars.EticaSmartContractAddress, solutionSlot, common.BytesToHash(solutionSeal[:]))

	fmt.Printf("Updated randomxSealSolutions:\n")
	challengeHex := "0x" + hex.EncodeToString(challengeNumber[:])
	fmt.Printf("Challenge Number: %s\n", challengeHex)
	fmt.Printf("Challenge Number: %x\n", challengeNumber)
	fmt.Printf("Miner Address: %s\n", miner.Hex())
	fmt.Printf("Nonce: 0x%x\n", nonce)
	fmt.Printf("claimedTarget: %s\n", claimedTarget.String())
	fmt.Printf("Packed bytes: 0x%x\n", packed) // Add this line to see the packed bytes
	fmt.Printf("Solution Seal: %s\n", solutionSeal.Hex())
}

/*
func calculateStorageSlot(challengeNumber [32]byte, minerAddress common.Address) common.Hash {
	baseSlot := common.BigToHash(big.NewInt(70))
	challengeNumberHash := crypto.Keccak256Hash(
		challengeNumber[:],
		baseSlot.Bytes(),
	)
	finalSlot := crypto.Keccak256Hash(
		minerAddress.Bytes(),
		challengeNumberHash.Bytes(),
	)
	return finalSlot
}

func updateRandomXState(statedb *state.StateDB, challengeNumber [32]byte, solution []byte, miner common.Address, difficulty *big.Int) {
	solutionSlot := calculateStorageSlot(challengeNumber, miner)
	existingSolution := statedb.GetState(vars.EticaSmartContractAddress, solutionSlot)
	if existingSolution != (common.Hash{}) {
		fmt.Println("Solution already exists, not updating")
		return
	}
	combinedBytes := append(solution, difficulty.Bytes()...)
	solutionHash := crypto.Keccak256Hash(combinedBytes)
	statedb.SetState(vars.EticaSmartContractAddress, solutionSlot, solutionHash)
	fmt.Printf("Updated randomxSealSolutions:\n")
	fmt.Printf("Challenge Number: %x\n", challengeNumber)
	fmt.Printf("Miner Address: %s\n", miner.Hex())
	fmt.Printf("Solution Hash: %s\n", solutionHash.Hex())
} */

/*
func calculateStorageSlot(challengeNumber *big.Int, minerAddress common.Address) common.Hash {
	// The slot of randomxSealSolutions is 70
	baseSlot := common.BigToHash(big.NewInt(70))

	// Calculate the slot for the first level of mapping
	challengeNumberHash := crypto.Keccak256Hash(
		challengeNumber.Bytes(),
		baseSlot.Bytes(),
	)

	// Calculate the slot for the second level of mapping
	finalSlot := crypto.Keccak256Hash(
		minerAddress.Bytes(),
		challengeNumberHash.Bytes(),
	)

	return finalSlot
}

func updateRandomXState(statedb *state.StateDB, challengeNumber *big.Int, solution []byte, miner common.Address, difficulty *big.Int) {
	// Calculate storage slot
	solutionSlot := calculateStorageSlot(challengeNumber, miner)

	// Check if solution already exists
	existingSolution := statedb.GetState(vars.EticaSmartContractAddress, solutionSlot)
	if existingSolution != (common.Hash{}) {
		// Solution already exists, do not update
		return
	}

	// Calculate Keccak256 hash of (solution, difficulty)
	combinedBytes := append(solution, difficulty.Bytes()...)
	solutionHash := crypto.Keccak256Hash(combinedBytes)

	// Update solution
	statedb.SetState(vars.EticaSmartContractAddress, solutionSlot, solutionHash)

	fmt.Printf("Updated randomxSealSolutions:\n")
	fmt.Printf("Challenge Number: %x\n", challengeNumber)
	fmt.Printf("Miner Address: %s\n", miner.Hex())
	fmt.Printf("Solution Hash: %s\n", solutionHash.Hex())
}
*/
