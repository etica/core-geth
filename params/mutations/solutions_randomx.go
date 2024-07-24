package mutations

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"unsafe"
)

// CheckSolutionWithTarget verifies a mining solution using RandomX
func CheckSolutionWithTarget(vm unsafe.Pointer, blockHeader []byte, nonce []byte, solution []byte, target []byte) (bool, error) {
	if vm == nil {
		return false, errors.New("RandomX VM is not initialized")
	}

	// Combine block header and nonce
	input := append(blockHeader, nonce...)

	// Calculate the hash
	hash := CalculateHash(vm, input)

	// Compare the hash with the provided solution
	if !bytes.Equal(hash, solution) {
		return false, errors.New("solution does not match calculated hash")
	}

	// Check if the hash meets the target difficulty
	if bytes.Compare(hash, target) > 0 {
		return false, errors.New("hash does not meet target difficulty")
	}

	return true, nil
}

func CheckRandomxSolution(vm unsafe.Pointer, blobWithNonce []byte, expectedHash []byte, claimedTarget *big.Int, blockHeight uint64, seedHash []byte) (bool, error) {
	if vm == nil {
		return false, fmt.Errorf("RandomX VM is not initialized")
	}

	calculatedHash := calculateRandomXHash(blobWithNonce, seedHash)

	if !bytes.Equal(calculatedHash, expectedHash) {
		return false, fmt.Errorf("expectedHash does not match calculated hash")
	}

	reversedHash := reverseBytes(calculatedHash)
	// Convert calculated hash to big.Int
	reversedHashInt := new(big.Int).SetBytes(reversedHash)

	fmt.Printf("Calculated Hash: %x\n", calculatedHash)
	fmt.Printf("Reversed Hash:   %x\n", reversedHash)
	fmt.Printf("Expected Hash:   %x\n", expectedHash)
	fmt.Printf("blobWithNonce:   %x\n", blobWithNonce)
	fmt.Printf("seedHash:        %x\n", seedHash)

	fmt.Printf("Target (hex):    %x\n", claimedTarget.Bytes())
	fmt.Printf("Reversed Hash (decimal): %s\n", reversedHashInt.String())
	fmt.Printf("Target (decimal):          %s\n", claimedTarget.String())

	// Compare hash with target
	comparisonResult := reversedHashInt.Cmp(claimedTarget)

	// Check if the hash meets the target difficulty
	if comparisonResult > 0 {
		return false, fmt.Errorf("hash does not meet claimed target difficulty (hash: %s, target: %s)", reversedHashInt.String(), claimedTarget.String())
	}

	return true, nil

}

func reverseBytes(data []byte) []byte {
	reversed := make([]byte, len(data))
	for i := range data {
		reversed[i] = data[len(data)-1-i]
	}
	return reversed
}

func calculateRandomXHash(blobWithNonce, seedHash []byte) []byte {
	flags := FlagDefault
	cache := InitRandomX(flags)
	if cache == nil {
		panic("Failed to allocate RandomX cache")
	}
	defer DestroyRandomX(cache)

	InitCache(cache, seedHash)

	vm := CreateVM(cache, flags)
	if vm == nil {
		panic("Failed to create RandomX VM")
	}
	defer DestroyVM(vm)

	hash := CalculateHash(vm, blobWithNonce)

	return hash
}

// Helper function to calculate target from difficulty
func calculateTarget(difficulty *big.Int) []byte {
	maxTarget := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	maxTarget.Sub(maxTarget, big.NewInt(1))
	target := new(big.Int).Div(maxTarget, difficulty)
	targetBytes := make([]byte, 32)
	target.FillBytes(targetBytes)
	return targetBytes
}

// CheckSolution verifies a mining solution using RandomX
func CheckSolution(vm unsafe.Pointer, blockHeader []byte, nonce []byte, solution []byte, difficulty *big.Int) (bool, error) {
	if vm == nil {
		return false, errors.New("RandomX VM is not initialized")
	}

	// Combine block header and nonce
	input := append(blockHeader, nonce...)

	// Calculate the hash
	hash := CalculateHash(vm, input)

	// Compare the hash with the provided solution
	if !bytes.Equal(hash, solution) {
		return false, errors.New("solution does not match calculated hash")
	}

	// Convert hash to big.Int for comparison with difficulty
	hashInt := new(big.Int).SetBytes(hash)

	// Calculate the maximum target (2^256 - 1)
	maxTarget := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	maxTarget.Sub(maxTarget, big.NewInt(1))

	// Calculate the current target based on the difficulty
	currentTarget := new(big.Int).Div(maxTarget, difficulty)

	// Check if the hash is less than or equal to the current target
	if hashInt.Cmp(currentTarget) > 0 {
		return false, errors.New("hash does not meet target difficulty")
	}

	return true, nil
}

// Helper function to convert hex string to bytes
func hexToBytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
