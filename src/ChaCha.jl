#=
An implementation of ChaCha20/20 and ChaCha20/12
for CSPRNG.
=#

module ChaCha

using Core.Intrinsics: llvmcall
using CUDA
using StaticArrays

# ChaCha block size is 32 * 16 bits = 64 bytes
const CHACHA_BLOCK_SIZE_U32 = 16
const CHACHA_BLOCK_SIZE = div(32 * 16, 8)

@inline lrot32(x, n) = (x << n) | (x >> (32 - n))
@inline lrot32(x::UInt32, n::UInt32) = llvmcall(
    ("""
     declare i32 @llvm.fshl.i32(i32, i32, i32)
     define i32 @entry(i32, i32, i32) #0 {
     3:
        %res = call i32 @llvm.fshl.i32(i32 %0, i32 %0, i32 %1)
        ret i32 %res
     }
     attributes #0 = { alwaysinline }
     """, "entry"), UInt32, Tuple{UInt32, UInt32}, x, n)

@inline function _QR!(x, a, b, c, d)
    @inbounds begin
        x[a] += x[b]; x[d] ⊻= x[a]; x[d] = lrot32(x[d], UInt32(16))
        x[c] += x[d]; x[b] ⊻= x[c]; x[b] = lrot32(x[b], UInt32(12))
        x[a] += x[b]; x[d] ⊻= x[a]; x[d] = lrot32(x[d],  UInt32(8))
        x[c] += x[d]; x[b] ⊻= x[c]; x[b] = lrot32(x[b],  UInt32(7))
    end
end

@inline function store_u64!(x::AbstractVector{UInt32}, u::UInt64, idx)
    x[idx] = UInt32(u & 0xffffffff)
    x[idx+1] = UInt32((u >> 32) & 0xffffffff)
end

@inline function add_u64!(x::AbstractVector{UInt32}, u::UInt64, idx)
    x[idx] += UInt32(u & 0xffffffff)
    x[idx+1] += UInt32((u >> 32) & 0xffffffff)
end

#=
Methods for constructing and using the initial ChaCha state

Under Bernstein's construction of the cipher (using a 64-bit nonce
and a 64-bit counter), the initial state looks as follows:

   cccccccc  cccccccc  cccccccc  cccccccc
   kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
   kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
   bbbbbbbb  bbbbbbbb  nnnnnnnn  nnnnnnnn

c = constant
k = key
b = block count
n = nonce

=#

function _cuda_chacha_set_initial_state!(state, key, nonce, counter)
    i = 16 * (blockIdx().x - 1) + 1
    counter += blockIdx().x - 1
    _chacha_set_initial_state!(state, key, nonce, counter, i)
    return
end

function _cuda_chacha_add_initial_state!(state, key, nonce, counter)
    i = 16 * (blockIdx().x - 1) + 1
    counter += blockIdx().x - 1
    _chacha_add_initial_state!(state, key, nonce, counter, i)
    return
end

@inline function _chacha_set_initial_state!(state, key, nonce, counter, i = 1)
    @inbounds begin
        state[i] = UInt32(0x61707865)
        state[i+1] = UInt32(0x3320646e)
        state[i+2] = UInt32(0x79622d32)
        state[i+3] = UInt32(0x6b206574)

        # There's probably a better way to copy memory
        # from `key` into `state` than this. Unfortunately,
        # methods like
        #
        #       state[i+4:i+11] .= key
        #
        # run into issues when `state` is a CUDA array. It's
        # not currently clear what the source of this problem
        # is but it's worth looking into further.
        u = zero(eltype(i))
        state[i+4] = key[u+1]
        state[i+5] = key[u+2]
        state[i+6] = key[u+3]
        state[i+7] = key[u+4]
        state[i+8] = key[u+5]
        state[i+9] = key[u+6]
        state[i+10] = key[u+7]
        state[i+11] = key[u+8]

        store_u64!(state, counter, i+12)
        store_u64!(state, nonce, i+14)
    end
end

@inline function _chacha_add_initial_state!(state, key, nonce, counter, i = 1)
    @inbounds begin
        state[i] += UInt32(0x61707865)
        state[i+1] += UInt32(0x3320646e)
        state[i+2] += UInt32(0x79622d32)
        state[i+3] += UInt32(0x6b206574)

        u = zero(eltype(i))
        state[i+4] += key[u+1]
        state[i+5] += key[u+2]
        state[i+6] += key[u+3]
        state[i+7] += key[u+4]
        state[i+8] += key[u+5]
        state[i+9] += key[u+6]
        state[i+10] += key[u+7]
        state[i+11] += key[u+8]

        add_u64!(state, counter, i+12)
        add_u64!(state, nonce, i+14)
    end
end


#=

ChaCha block function

=#

function chacha_blocks!(
    buffer::AbstractVector{UInt32},
    key,
    nonce::UInt64,
    counter::UInt64,
    nblocks = 1;
    doublerounds = 10,
)
    for i ∈ 1:nblocks
        block_start = CHACHA_BLOCK_SIZE_U32 * (i - 1) + 1
        block_end = block_start + CHACHA_BLOCK_SIZE_U32 - 1
        state = view(buffer, block_start:block_end)

        _chacha_set_initial_state!(state, key, nonce, counter, 1)

        # Perform alternating rounds of columnar
        # quarter-rounds and diagonal quarter-rounds
        for i = 1:doublerounds
            # Columnar rounds
            _QR!(state, 1, 5, 9, 13)
            _QR!(state, 2, 6, 10, 14)
            _QR!(state, 3, 7, 11, 15)
            _QR!(state, 4, 8, 12, 16)

            # Diagonal rounds
            _QR!(state, 1, 6, 11, 16)
            _QR!(state, 2, 7, 12, 13)
            _QR!(state, 3, 8, 9, 14)
            _QR!(state, 4, 5, 10, 15)
        end

        # Finish by adding the initial state back to
        # the original state, so that the operations
        # are no longer invertible
        _chacha_add_initial_state!(state, key, nonce, counter, 1)

        counter += 1
    end

    counter
end

function chacha_blocks!(
    buffer::CuArray, key, nonce::UInt64, counter::UInt64, nblocks = 1; doublerounds = 10
)
    # We can only create 2^16-1 thread blocks at a given time, so when nblocks
    # exceeds that we must iterate over the state array in chunks
    for chunk = 0:2^16-1:nblocks-1
        chunk_blocks = min(nblocks - chunk, 2^16-1)
        chunk_start = chunk * CHACHA_BLOCK_SIZE_U32 + 1
        chunk_end = chunk_start + chunk_blocks * CHACHA_BLOCK_SIZE_U32 - 1
        state = view(buffer, chunk_start:chunk_end)

        @cuda blocks=chunk_blocks _cuda_chacha_set_initial_state!(state, key, nonce, counter)
        @cuda blocks=chunk_blocks threads=4 _cuda_chacha_rounds!(state, doublerounds)
        @cuda blocks=chunk_blocks _cuda_chacha_add_initial_state!(state, key, nonce, counter)
    end

    counter + nblocks
end

function _cuda_chacha_rounds!(state, doublerounds)
    block = 16 * (blockIdx().x - 1)
    i = threadIdx().x
    idx = block + i

    # Only operate on a slice of the state corresponding to
    # the thread block
    state_slice = view(state, block+1:block+16)

    # Pre-compute the indices that this thread will use to
    # perform its diagonal rounds
    dgc1 = i
    dgc2 = 5 + (dgc1 % 4)
    dgc3 = 9 + (dgc2 % 4)
    dgc4 = 13 + (dgc3 % 4)

    # Perform alternating rounds of columnar quarter-
    # rounds and diagonal quarter-rounds
    #
    # Each thread in the same block runs its rounds in parallel
    for _ = 1:doublerounds
        # Columnar rounds
        _QR!(state_slice, i, i + 4, i + 8, i + 12)
        CUDA.threadfence_block()

        # Diagonal rounds
        _QR!(state_slice, dgc1, dgc2, dgc3, dgc4)
        CUDA.threadfence_block()
    end

    nothing
end

export CHACHA_BLOCK_SIZE, CHACHA_BLOCK_SIZE_U32
export chacha_blocks!

end # module
