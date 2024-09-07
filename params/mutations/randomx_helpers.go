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
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params/vars"
)

const nonceOffset = 39
const reservedExtranonceSize = 8 // 8 bytes reservedExtranonce (guaranties uniqueness and prevent collisions, each miner mines with a specific blob)
const reservedOffset = 55

func initRandomXSystem(flags RandomXFlags, seed []byte) error {

	// Lock the global mutexes for the cache and VM
	randomxCacheMutex.Lock()
	defer randomxCacheMutex.Unlock()
	randomxVmMutex.Lock()
	defer randomxVmMutex.Unlock()

	// Always destroy the VM and cache before reinitializing
	if globalRandomXVM != nil {
		DestroyVM(globalRandomXVM)
		globalRandomXVM = nil
	}
	if globalRandomXCache != nil {
		DestroyRandomX(globalRandomXCache)
		globalRandomXCache = nil
	}

	// Reinitialize cache and VM
	globalRandomXCache = InitRandomX(flags)
	if globalRandomXCache == nil {
		return fmt.Errorf("failed to allocate RandomX cache")
	}
	InitCache(globalRandomXCache, seed)

	globalRandomXVM = CreateVM(globalRandomXCache, flags)
	if globalRandomXVM == nil {
		return fmt.Errorf("failed to create RandomX VM")
	}

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

	//txData := tx.Data()
	//txDataHex := hex.EncodeToString(txData)
	//fmt.Printf("Verifying Etica transaction data (hex): 0x%s\n", txDataHex)
	//fmt.Printf("Verifying Etica transaction data (raw): %v\n", txData)
	//fmt.Printf("Verifying Etica transaction: %s\n", tx.Hash().Hex())

	// Check if tx is nil
	if tx == nil {
		return fmt.Errorf("transaction is nil")
	}

	// Check if statedb is nil
	if statedb == nil {
		return fmt.Errorf("statedb is nil")
	}

	var contractAddress common.Address

	// Determine which contract address to use based on the chainId START
	if chainId == 61803 { // Etica mainnet
		contractAddress = vars.EticaSmartContractAddress
	} else if chainId == 61888 { // Crucible testnet
		contractAddress = vars.CrucibleSmartContractAddress
	} else {
		return fmt.Errorf("unsupported chain ID: %d", chainId)
	}

	if (chainId == 61803 && contractAddress != vars.EticaSmartContractAddress) || (chainId == 61888 && contractAddress != vars.CrucibleSmartContractAddress) {
		return fmt.Errorf("wrong contractAddress for this chain ID: %d", chainId)
	}
	// Determine which contract address to use based on the chainId END
	// Now all checks are done, contractAddress is fully checked and contains the right smart contract address

	if tx.To() == nil || *tx.To() != contractAddress {
		//Transaction is not to Etica smart contract
		return nil
	}

	// Transaction is to Etica smart contract

	// Check if the transaction is a Etica Smart Contract calling the mintrandomX() function
	if !IsSolutionProposal(tx.Data()) {
		// Transaction is not a Etica Smart Contract mintrandomX call
		return nil
	}

	nonce, blockHeader, challengeNumber, randomxHash, claimedTarget, seedHash, extraNonce, err := ExtractSolutionData(tx.Data())
	if err != nil {
		if err.Error() == "Invalid function selector" {
			return nil // Not an error, just not the transaction we're looking for
		}
		//fmt.Printf("Error extracting solution data: %v\n", err)
		log.Error("Error extracting solution data")
		return err
	}

	// check inputs types | START

	// Check nonce (bytes4)
	if len(nonce) != 4 {
		return fmt.Errorf("invalid nonce length: expected 4 bytes, got %d bytes", len(nonce))
	}

	// Slices (add nil checks)
	if blockHeader == nil {
		return fmt.Errorf("blockHeader is nil")
	}

	if len(blockHeader) != 76 {
		return fmt.Errorf("invalid blockHeader length: expected 76 bytes, got %d bytes", len(blockHeader))
	}

	if len(challengeNumber) != 32 {
		return fmt.Errorf("invalid challengeNumber length: expected 32 bytes, got %d bytes", len(challengeNumber))
	}

	if randomxHash == nil {
		return fmt.Errorf("randomxHash is nil")
	}

	if len(randomxHash) != 32 {
		return fmt.Errorf("invalid randomxHash length: expected 32 bytes, got %d bytes", len(randomxHash))
	}

	// Check claimedTarget (uint)
	if claimedTarget == nil {
		return fmt.Errorf("claimedTarget is nil")
	}
	if claimedTarget.Sign() < 0 {
		return fmt.Errorf("claimedTarget must be non-negative")
	}

	if claimedTarget.BitLen() > 256 {
		return fmt.Errorf("claimedTarget exceeds maximum allowed value (256 bits)")
	}

	if seedHash == nil {
		return fmt.Errorf("seedHash is nil")
	}

	if len(seedHash) != 32 {
		return fmt.Errorf("invalid seedHash length: expected 32 bytes, got %d bytes", len(seedHash))
	}

	if len(extraNonce) != 8 {
		return fmt.Errorf("invalid extraNonce length: expected 8 bytes, got %d bytes", len(extraNonce))
	}

	// check inputs types | END

	// CHECKS SUBMITED TARGET IS INFERIOR TO SMART CONTRACT miningTarget | START
	// verify claimedTarget is inferior to smart contract miningTarget to avoid contract storage spam:
	miningTargetSlot := calculateMiningTargetSlot()
	currentMiningTarget := statedb.GetState(contractAddress, miningTargetSlot)

	// Convert currentMiningTarget to *big.Int
	currentMiningTargetBigInt := new(big.Int).SetBytes(currentMiningTarget.Bytes())

	// Compare claimedTarget with currentMiningTarget
	if claimedTarget.Cmp(currentMiningTargetBigInt) > 0 {
		return fmt.Errorf("claimedTarget (%s) is greater than currentMiningTarget (%s)", claimedTarget.String(), currentMiningTargetBigInt.String())
	}
	// CHECKS SUBMITED TARGET IS INFERIOR TO SMART CONTRACT miningTarget | END

	// CHECKS SUBMITED CHALLENGE NUMBER CORRESPONDS TO CURRENT SMART CONTRACT challengeNumber | START
	// verify submited challengeNumber corresponds to smart contract challengeNumber to avoid contract storage spam:
	// Check for empty values (should never happen thanks to txs inputs verifications):
	if challengeNumber == [32]byte{} {
		return fmt.Errorf("submitted challengeNumber is empty")
	}

	challengeNumberSlot := calculateChallengeNumberSlot()
	currentChallengeNumber := statedb.GetState(contractAddress, challengeNumberSlot)
	fmt.Printf("challengeNumber: %v\n", challengeNumber)
	fmt.Printf("currentChallengeNumber: %v\n", currentChallengeNumber)

	if currentChallengeNumber == (common.Hash{}) {
		return fmt.Errorf("current challengeNumber from smart contract is empty")
	}

	if !bytes.Equal(challengeNumber[:], currentChallengeNumber[:]) {
		return fmt.Errorf("wrong challengeNumber: expected %x, got %x", currentChallengeNumber, challengeNumber)
	}
	// CHECKS SUBMITED CHALLENGE NUMBER CORRESPOND TO CURRENT SMART CONTRACT challengeNumber  | END

	// CHECKS SUBMITED BLOCKHEADER CORRESPONDS TO CURRENT SMART CONTRACT randomxBlob | START
	// verify submited blockHeader corresponds to smart contract randomxBlob to avoid contract storage spam:
	// Check for empty values (should never happen thanks to txs inputs verifications):
	if blockHeader == nil || len(blockHeader) == 0 {
		return fmt.Errorf("submitted blockHeader is nil or empty")
	}

	blockHeaderFirstPartSlot := calculateBlockHeaderFirstPartSlot()
	currentBlockHeaderFirstPart := statedb.GetState(contractAddress, blockHeaderFirstPartSlot)

	fmt.Printf("blockHeader: %v\n", blockHeader)
	fmt.Printf("currentBlockHeaderFirstPart: %v\n", currentBlockHeaderFirstPart)

	// Now compare the retrieved currentBlockHeaderFirstPart with the submitted blockHeader first 32bytes
	if !bytes.Equal(blockHeader[:32], currentBlockHeaderFirstPart.Bytes()) {
		return fmt.Errorf("wrong blockHeader: expected %x, got %x", currentBlockHeaderFirstPart.Bytes(), blockHeader)
	}

	// CHECKS SUBMITED BLOCKHEADER CORRESPONDS TO CURRENT SMART CONTRACT randomxBlob  | END

	// Initialize RandomX system if needed
	if globalRandomXCache == nil || globalRandomXVM == nil || !bytes.Equal(globalSeedHash, seedHash) {
		if err := initRandomXSystem(FlagDefault, seedHash); err != nil {
			return err // Returns Error initializing RandomX system
		}
		globalSeedHash = seedHash // Update the global seedHash
	}

	// Keep it for now, will remove these logs
	//fmt.Println("Transaction is a mintrandomX call")
	//fmt.Printf("Extracted block header: %x\n", blockHeader)
	//fmt.Printf("Extracted nonce: %x\n", nonce)
	//fmt.Printf("Extracted ExtraNonce: %x\n", nonce)
	//fmt.Printf("Extracted claimedTarget: %s\n", claimedTarget.String())
	//fmt.Printf("SeedHash: %v\n", seedHash)
	//fmt.Printf("challengeNumber: %v\n", challengeNumber)

	//fmt.Println(" ****** Performing RandomX verification... ********")
	//fmt.Printf("randomxHash: %v\n", randomxHash)

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
		common.LeftPadBytes(challengeNumber[:], 32),
	)

	// Step 3: Truncate extraNonceHash to extraNonceSize
	truncatedExtraNonceHash := extraNonceHash[:8]

	// Step 4: Insert the truncated extraNonceHash at reservedOffset (55 bytes)
	copy(blobWithNonce[reservedOffset:], truncatedExtraNonceHash)

	// valid, err := CheckSolution(vm, blockHeader, nonce, correctSolution, difficulty) -- > replaced by next line:
	valid, err := CheckRandomxSolution(globalRandomXVM, blobWithNonce, randomxHash, claimedTarget, seedHash)

	if err != nil {
		return err
	}
	if valid {

		// Update the RandomX state
		updateRandomXState(statedb, challengeNumber, nonce, from, randomxHash, claimedTarget, seedHash, contractAddress)
		// return something here to main process for success message

	} else {
		return fmt.Errorf("invalid RandomX solution")
	}

	return nil
}

func IsSolutionProposal(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	functionSelector := data[:4]
	// Replace with actual selector for mintrandomX
	expectedSelector := []byte{0x03, 0x7d, 0x2f, 0x35} // Actual selector for mintrandomX f0a9b55b
	return bytes.Equal(functionSelector, expectedSelector)
}

func ExtractSolutionData(data []byte) (nonce [4]byte, blockHeader []byte, challengeNumber [32]byte, randomxHash []byte, claimedTarget *big.Int, seedHash []byte, extraNonce [8]byte, err error) {

	// Check if data is nil
	if data == nil {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Input data is nil")
	}

	// Check if the data is long enough to contain all required fields
	// 4 (selector) + 32 (nonce) + 80 (blockHeader) + 32 (challengeNumber) + 32 (randomxHash) + 32 (claimedTarget) + 32 (seedHash) + 8 (extraNonce) = 252 bytes
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
	if len(data) < 68 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for blockHeader offset")
	}
	blockHeaderOffset := new(big.Int).SetBytes(data[36:68]).Uint64()

	// Extract challengeNumber (bytes32)
	if len(data) < 100 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for challengeNumber")
	}
	copy(challengeNumber[:], data[68:100])
	fmt.Printf("Extracted challengeNumber: %x\n", challengeNumber)

	// Extract randomxHash offset
	// Extract randomxHash offset (Add bounds check)
	if len(data) < 132 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for randomxHash offset")
	}
	randomxHashOffset := new(big.Int).SetBytes(data[100:132]).Uint64()

	// Extract claimedTarget (uint256)
	if len(data) < 164 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for claimedTarget")
	}
	claimedTarget = new(big.Int).SetBytes(data[132:164])
	fmt.Printf("Extracted claimedTarget: %d\n", claimedTarget)

	// Extract seedHash offset
	if len(data) < 196 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for seedHash offset")
	}
	seedHashOffset := new(big.Int).SetBytes(data[164:196]).Uint64()

	// Extract extraNonce (8 bytes)
	if len(data) < 204 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for extraNonce")
	}
	copy(extraNonce[:], data[196:204])

	// Extract dynamic fields
	maxFieldSize := uint64(1024 * 1024) // 1MB max size for dynamic fields

	// Extract blockHeader (dynamic bytes)
	if blockHeaderOffset > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Invalid blockHeader offset")
	}
	blockHeaderStart := 4 + blockHeaderOffset
	if blockHeaderStart+32 > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for blockHeader length")
	}
	blockHeaderLength := new(big.Int).SetBytes(data[blockHeaderStart : blockHeaderStart+32]).Uint64()

	if blockHeaderLength == 0 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("blockHeader length cannot be zero")
	}
	if blockHeaderLength > maxFieldSize {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("blockHeader length exceeds maximum allowed size")
	}

	blockHeaderStart += 32
	blockHeaderEnd := blockHeaderStart + blockHeaderLength
	if blockHeaderEnd > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Invalid blockHeader length")
	}
	blockHeader = make([]byte, blockHeaderLength)
	copy(blockHeader, data[blockHeaderStart:blockHeaderEnd])

	// Extract randomxHash (dynamic bytes)
	if randomxHashOffset > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Invalid randomxHash offset")
	}
	randomxHashStart := 4 + randomxHashOffset
	if randomxHashStart+32 > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for randomxHash length")
	}
	randomxHashLength := new(big.Int).SetBytes(data[randomxHashStart : randomxHashStart+32]).Uint64()

	if randomxHashLength == 0 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("randomxHash length cannot be zero")
	}
	if randomxHashLength > maxFieldSize {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("randomxHash length exceeds maximum allowed size")
	}

	randomxHashStart += 32
	randomxHashEnd := randomxHashStart + randomxHashLength
	if randomxHashEnd > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Invalid randomxHash length")
	}
	randomxHash = make([]byte, randomxHashLength)
	copy(randomxHash, data[randomxHashStart:randomxHashEnd])

	// Extract seedHash (dynamic bytes)
	seedHashStart := 4 + seedHashOffset
	if seedHashStart+32 > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for seedHash length")
	}
	seedHashLength := new(big.Int).SetBytes(data[seedHashStart : seedHashStart+32]).Uint64()

	if seedHashLength == 0 {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("seedHash length cannot be zero")
	}
	if seedHashLength > maxFieldSize {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("seedHash length exceeds maximum allowed size")
	}

	seedHashStart += 32
	if seedHashStart+32 > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Data too short for seedHash data")
	}
	seedHashEnd := seedHashStart + seedHashLength
	if seedHashEnd > uint64(len(data)) {
		return [4]byte{}, nil, [32]byte{}, nil, nil, nil, [8]byte{}, errors.New("Invalid seedHash length")
	}
	seedHash = make([]byte, seedHashLength)
	copy(seedHash, data[seedHashStart:seedHashEnd])

	return nonce, blockHeader, challengeNumber, randomxHash, claimedTarget, seedHash, extraNonce, nil
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

func calculateChallengeNumberSlot() common.Hash {
	// The storage slot for challengeNumber is at position 18
	challengeNumberSlot := big.NewInt(18)

	// Left-pad the slot with zeroes to 32 bytes (256 bits)
	slotBytes := common.LeftPadBytes(challengeNumberSlot.Bytes(), 32)

	// Return the storage slot as a common.Hash
	return common.BytesToHash(slotBytes)
}

func calculateBlockHeaderFirstPartSlot() common.Hash {
	// The storage slot for randomxBlobfirstpart is at position 74
	randomxBlobfirstpartSlot := big.NewInt(74)

	// Left-pad the slot with zeroes to 32 bytes (256 bits)
	slotBytes := common.LeftPadBytes(randomxBlobfirstpartSlot.Bytes(), 32)

	// Return the storage slot as a common.Hash
	return common.BytesToHash(slotBytes)
}

func updateRandomXState(statedb *state.StateDB, challengeNumber [32]byte, nonce [4]byte, miner common.Address, randomxHash []byte, claimedTarget *big.Int, seedHash []byte, contractAddress common.Address) {

	sendernoncepacked := make([]byte, len(miner.Bytes())+len(nonce[:]))
	copy(sendernoncepacked[:len(miner.Bytes())], miner.Bytes())
	copy(sendernoncepacked[len(miner.Bytes()):], nonce[:])

	senderNonceHash := crypto.Keccak256Hash(sendernoncepacked)

	solutionSlot := calculateStorageSlot(challengeNumber, senderNonceHash)
	existingSolution := statedb.GetState(contractAddress, solutionSlot)

	challengeHex := "0x" + hex.EncodeToString(challengeNumber[:])

	if existingSolution != (common.Hash{}) {
		log.Info("RandomX transaction already verified, not updating",
			"challengeNumber", challengeHex,
			"miner", miner.Hex(),
			"senderNonceHash", senderNonceHash.Hex(),
			"existingSolution", existingSolution.Hex(),
		)
		return
	}

	// Pack nonce, claimedTarget, seedHash, and randomxHash
	packed := make([]byte, 4+32+len(seedHash)+len(randomxHash))
	copy(packed[:4], nonce[:])
	claimedTarget.FillBytes(packed[4:36])
	copy(packed[36:36+len(seedHash)], seedHash)
	copy(packed[36+len(seedHash):], randomxHash)

	// Calculate Keccak256 hash
	solutionSeal := crypto.Keccak256Hash(packed)

	statedb.SetState(contractAddress, solutionSlot, common.BytesToHash(solutionSeal[:]))

	log.Info("Successfully verified new ETI RandomX block",
		"challengeNumber", challengeHex,
		"miner", miner.Hex(),
		"senderNonceHash", senderNonceHash.Hex(),
		"solutionSeal", solutionSeal.Hex(),
	)
}
