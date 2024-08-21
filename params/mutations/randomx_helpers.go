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

func initRandomXSystem(flags RandomXFlags, seed []byte) error {

	fmt.Printf("*999-*-*999*-**-*999*- ------------- INSIDE initRandomXSystem() ---------- *999-*-*999*-**-*999* *-*-*-*-*-*-**-*")
	// Always destroy the VM and cache before reinitializing
	if globalRandomXVM != nil {
		fmt.Printf("*999-*-*999*-**-*999*- ----- globalRandomXVM empty calling -------- DestroyVM ---------- *999-*-*999*-**-*999* *-*-*-*-*-*-**-*")
		DestroyVM(globalRandomXVM)
		globalRandomXVM = nil
	}
	if globalRandomXCache != nil {
		fmt.Printf("*999-*-*999*-**-*999*- ----- globalRandomXCache empty calling -------- DestroyRandomX ---------- *999-*-*999*-**-*999* *-*-*-*-*-*-**-*")
		DestroyRandomX(globalRandomXCache)
		globalRandomXCache = nil
	}

	// Reinitialize cache and VM
	globalRandomXCache = InitRandomX(flags)
	if globalRandomXCache == nil {
		fmt.Printf("*999-*-*999*-**-*999*- ----- InitRandomX error failed to allocate RandomX cache --- *999-*-*999*-**-*999* *-*-*-*-*-*-**-*")
		return fmt.Errorf("failed to allocate RandomX cache")
	}
	InitCache(globalRandomXCache, seed)

	globalRandomXVM = CreateVM(globalRandomXCache, flags)
	if globalRandomXVM == nil {
		fmt.Printf("*999-*-*999*-**-*999*- ----- InitRandomX error failed to create RandomX VM --- *999-*-*999*-**-*999* *-*-*-*-*-*-**-*")
		return fmt.Errorf("failed to create RandomX VM")
	}

	fmt.Printf("*-*-** 999999999 -**-*-*- ------------- initRandomXSystem() SUCCESS ---------- *-*-*-*999999999999 *-*-**-*")

	return nil
}

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

func VerifyEticaTransaction(tx *types.Transaction, statedb *state.StateDB, chainId uint64) error {
	fmt.Printf("*-*-*-*-**-*-*-*-*-*-Verifying Etica transaction *-*-*-*-*-**-*-*-*-*-*-*-*-*-")
	fmt.Printf("Verifying Etica transaction: %s\n", tx.Hash().Hex())
	txData := tx.Data()
	txDataHex := hex.EncodeToString(txData)
	fmt.Printf("Verifying Etica transaction data (hex): 0x%s\n", txDataHex)
	fmt.Printf("Verifying Etica transaction data (raw): %v\n", txData)

	var contractAddress common.Address

	// Determine which contract address to use based on the chainId START
	if chainId == 61803 { // Etica mainnet
		contractAddress = vars.EticaSmartContractAddress
	} else if chainId == 818889 { // Crucible testnet
		contractAddress = vars.CrucibleSmartContractAddress
	} else {
		return fmt.Errorf("unsupported chain ID: %d", chainId)
	}

	fmt.Printf("------- µµµµ ---- µµµµ -- µµµµµ -- µµµµµ -----> contractAddress: %s\n", contractAddress)

	if (chainId == 61803 && contractAddress != vars.EticaSmartContractAddress) || (chainId == 818889 && contractAddress != vars.CrucibleSmartContractAddress) {
		fmt.Printf("wrong contractAddress for this chain ID contractAddress: %s\n", contractAddress)
		return fmt.Errorf("wrong contractAddress for this chain ID: %d", chainId)
	}
	// Determine which contract address to use based on the chainId END
	// Now all checks are done, contractAddress is fully checked and contains the right smart contract address

	fmt.Printf("------- µµµµ ---- µµµµ -- µµµµµ -- µµµµµ -----> EticaSmartContractAddress: %s\n", contractAddress)
	if tx.To() == nil || *tx.To() != contractAddress {
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
	/* cache := InitRandomX(FlagDefault)
	if cache == nil {
		return fmt.Errorf("failed to initialize RandomX cache")
	}
	defer DestroyRandomX(cache)

	vm := CreateVM(cache, FlagDefault)
	if vm == nil {
		return fmt.Errorf("failed to create RandomX")
	}
	defer DestroyVM(vm) */

	nonce, blockHeader, currentChallenge, randomxHash, claimedTarget, seedHash, extraNonce, err := ExtractSolutionData(tx.Data())
	if err != nil {
		if err.Error() == "Invalid function selector" {
			fmt.Println("Failed to Extract Solution Data, Invalid function selector")
			return nil // Not an error, just not the transaction we're looking for
		}
		fmt.Printf("Error extracting solution data: %v\n", err)
		return err
	}

	// CHECKS SUBMITED TARGET IS INFERIOR TO SMART CONTRACT miningTarget | START
	// verify claimedTarget is inferior to smart contract miningTarget to avoid contract storage spam:
	miningTargetSlot := calculateMiningTargetSlot()
	fmt.Printf("!!!!!! µµµµµµµµµµµµ !!!!!!!! µµµµµµµµµµµµµ Mining Target Slot: %s\n", miningTargetSlot.Hex())
	currentMiningTarget := statedb.GetState(contractAddress, miningTargetSlot)
	fmt.Printf("!!!!!! µµµµµµµµµµµµ !!!!!!!! µµµµµµµµµµµµµ currentMiningTarget (hex): %s\n", currentMiningTarget.Hex())

	// Convert currentMiningTarget to *big.Int
	currentMiningTargetBigInt := new(big.Int).SetBytes(currentMiningTarget.Bytes())

	fmt.Printf("!!!!!! µµµµµµµµµµµµ !!!!!!!! µµµµµµµµµµµµµ currentMiningTargetBigInt (decimal): %s\n", currentMiningTargetBigInt.String())
	fmt.Printf("!!!!!! µµµµµµµµµµµµ !!!!!!!! µµµµµµµµµµµµµ currentMiningTargetBigInt (hex): %x\n", currentMiningTargetBigInt)

	// Compare claimedTarget with currentMiningTarget
	if claimedTarget.Cmp(currentMiningTargetBigInt) > 0 {
		return fmt.Errorf("claimedTarget (%s) is less than currentMiningTarget (%s)", claimedTarget.String(), currentMiningTargetBigInt.String())
	}
	// CHECKS SUBMITED TARGET IS INFERIOR TO SMART CONTRACT miningTarget | END

	// Initialize RandomX system if needed
	if globalRandomXCache == nil || globalRandomXVM == nil {
		fmt.Println("*1µ1µ1µ1µ1µ1µ1µ 1µ1µ1µ1µµ1µ1µ1µ1µ1µ - calling initRandomXSystem() because globalRandomXCache or globalRandomXVM is empty  1µ1µ1µ1µ1µ1µ1µ 1µ1µ1µ1µµ1µ1µ1µ1µ1µ")
		if err := initRandomXSystem(FlagDefault, seedHash); err != nil {
			fmt.Printf("Error in initRandomXSystem() initializing RandomX system: %v\n", err)
			return nil // Return nil to continue processing other transactions
		}
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
	valid, err := CheckRandomxSolution(globalRandomXVM, blobWithNonce, randomxHash, claimedTarget, blockHeight, seedHash)

	if err != nil {
		fmt.Printf("RandomX verification error: %v\n", err)
		return err
	}
	if valid {
		fmt.Println("RandomX verification passed")

		// Update the RandomX state
		updateRandomXState(statedb, currentChallenge, nonce, from, randomxHash, claimedTarget, seedHash, contractAddress)
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

func calculateStorageSlot(challengeNumber [32]byte, senderNonceHash common.Hash) common.Hash {
	// The slot of randomxSealSolutions is 70
	baseSlot := big.NewInt(70)

	// For the first level of mapping (challengeNumber)
	outerLocation := crypto.Keccak256Hash(
		challengeNumber[:],
		common.LeftPadBytes(baseSlot.Bytes(), 32),
	)

	// For the second level of mapping (minerAddress)
	finalSlot := crypto.Keccak256Hash(
		common.LeftPadBytes(senderNonceHash.Bytes(), 32),
		outerLocation.Bytes(),
	)

	return finalSlot
}

func calculateMiningTargetSlot() common.Hash {
	// The storage slot for miningTarget is at position 17
	miningTargetSlot := big.NewInt(17)

	// Left-pad the slot with zeroes to 32 bytes (256 bits)
	slotBytes := common.LeftPadBytes(miningTargetSlot.Bytes(), 32)

	// Return the storage slot as a common.Hash
	return common.BytesToHash(slotBytes)
}

func updateRandomXState(statedb *state.StateDB, challengeNumber [32]byte, nonce [4]byte, miner common.Address, randomxHash []byte, claimedTarget *big.Int, seedHash []byte, contractAddress common.Address) {

	sendernoncepacked := make([]byte, len(miner.Bytes())+len(nonce[:]))
	copy(sendernoncepacked[:len(miner.Bytes())], miner.Bytes())
	copy(sendernoncepacked[len(miner.Bytes()):], nonce[:])

	senderNonceHash := crypto.Keccak256Hash(sendernoncepacked)
	fmt.Printf("senderNonceHash: %s\n", senderNonceHash.Hex())

	solutionSlot := calculateStorageSlot(challengeNumber, senderNonceHash)
	fmt.Printf("solutionSlot: %s\n", solutionSlot)
	existingSolution := statedb.GetState(contractAddress, solutionSlot)
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

	statedb.SetState(contractAddress, solutionSlot, common.BytesToHash(solutionSeal[:]))

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
