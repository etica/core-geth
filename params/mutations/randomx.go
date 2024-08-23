package mutations

/*
#cgo CFLAGS: -I./include
#cgo linux LDFLAGS: -L./lib/linux -lrandomx -lstdc++
#cgo darwin LDFLAGS: -L./lib -lrandomx -lstdc++
#cgo windows LDFLAGS: -L./lib/windows -lrandomx -lstdc++ -lws2_32 -ladvapi32
#include "randomx.h"
*/
import "C"

import (
	"sync"
	"unsafe"
)

// RandomXFlags type to represent RandomX flags
type RandomXFlags uint32

const (
	// FlagDefault is the default RandomX flag
	FlagDefault RandomXFlags = C.RANDOMX_FLAG_DEFAULT

	FlagLargePages  RandomXFlags = C.RANDOMX_FLAG_LARGE_PAGES
	FlagHardAES     RandomXFlags = C.RANDOMX_FLAG_HARD_AES
	FlagFullMEM     RandomXFlags = C.RANDOMX_FLAG_FULL_MEM
	FlagJIT         RandomXFlags = C.RANDOMX_FLAG_JIT
	FlagSecure      RandomXFlags = C.RANDOMX_FLAG_SECURE
	FlagArgon2SSSE3 RandomXFlags = C.RANDOMX_FLAG_ARGON2_SSSE3
	FlagArgon2AVX2  RandomXFlags = C.RANDOMX_FLAG_ARGON2_AVX2
	FlagArgon2      RandomXFlags = C.RANDOMX_FLAG_ARGON2
)

var globalRandomXCache unsafe.Pointer
var globalRandomXVM unsafe.Pointer
var globalSeedHash []byte

// Use Mutexes to make sure Global RandmoX VM and Cache are not used by multiple processes at the same time to avoid unexpected behaviour
var randomxVmMutex sync.Mutex
var randomxCacheMutex sync.Mutex

// InitCache initializes a RandomX cache with the given seed
func InitCache(cache unsafe.Pointer, seed []byte) {
	C.randomx_init_cache((*C.struct_randomx_cache)(cache), unsafe.Pointer(&seed[0]), C.size_t(len(seed)))
}

// InitRandomX initializes RandomX with the given flags
func InitRandomX(flags RandomXFlags) unsafe.Pointer {
	return unsafe.Pointer(C.randomx_alloc_cache(C.randomx_flags(flags)))
}

// DestroyRandomX frees the RandomX cache
func DestroyRandomX(cache unsafe.Pointer) {
	C.randomx_release_cache((*C.struct_randomx_cache)(cache))
}

// CreateVM creates a new RandomX VM instance
func CreateVM(cache unsafe.Pointer, flags RandomXFlags) unsafe.Pointer {
	return unsafe.Pointer(C.randomx_create_vm(C.randomx_flags(flags), (*C.struct_randomx_cache)(cache), nil))
}

// DestroyVM destroys a RandomX VM instance
func DestroyVM(vm unsafe.Pointer) {
	C.randomx_destroy_vm((*C.struct_randomx_vm)(vm))
}

// CalculateHash calculates a RandomX hash
func CalculateHash(vm unsafe.Pointer, input []byte) []byte {
	output := make([]byte, C.RANDOMX_HASH_SIZE)
	C.randomx_calculate_hash((*C.struct_randomx_vm)(vm), unsafe.Pointer(&input[0]), C.size_t(len(input)), unsafe.Pointer(&output[0]))
	return output
}

// CalculateHashFirst calculates the first part of the RandomX hash
func CalculateHashFirst(vm unsafe.Pointer, input []byte) {
	C.randomx_calculate_hash_first((*C.struct_randomx_vm)(vm), unsafe.Pointer(&input[0]), C.size_t(len(input)))
}

// CalculateHashLast calculates the last part of the RandomX hash
func CalculateHashLast(vm unsafe.Pointer) []byte {
	output := make([]byte, C.RANDOMX_HASH_SIZE)
	C.randomx_calculate_hash_last((*C.struct_randomx_vm)(vm), unsafe.Pointer(&output[0]))
	return output
}

// HashSize returns the size of the RandomX hash
func HashSize() int {
	return int(C.RANDOMX_HASH_SIZE)
}
