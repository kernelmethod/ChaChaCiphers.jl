#=
An implementation of ChaCha20/20 and ChaCha20/12
for CSPRNG.
=#

module ChaCha

using CUDA
using SIMD
using StaticArrays

# ChaCha block size is 32 * 16 bits = 64 bytes
const CHACHA_BLOCK_SIZE_U32 = 16
const CHACHA_BLOCK_SIZE = div(32 * 16, 8)

@inline lrot32(x, n) = (x << n) | (x >> (32 - n))
@inline lrot32(x::Union{Vec,UInt32}, n) = bitrotate(x, n)

@inline @generated function rotatevector(x::Vec{N,T}, ::Val{M}) where {N,T,M}
    rotation = circshift(0:3, M)
    rotation = repeat(rotation, N ÷ 4)
    rotation += 4 * ((0:N-1) .÷ 4)
    rotation = Val(Tuple(rotation))
    :(shufflevector(x, $rotation))
end

macro _QR!(a, b, c, d)
    quote
        $(esc(a)) += $(esc(b)); $(esc(d)) ⊻= $(esc(a)); $(esc(d)) = lrot32($(esc(d)), 16);
        $(esc(c)) += $(esc(d)); $(esc(b)) ⊻= $(esc(c)); $(esc(b)) = lrot32($(esc(b)), 12);
        $(esc(a)) += $(esc(b)); $(esc(d)) ⊻= $(esc(a)); $(esc(d)) = lrot32($(esc(d)), 8);
        $(esc(c)) += $(esc(d)); $(esc(b)) ⊻= $(esc(c)); $(esc(b)) = lrot32($(esc(b)), 7);

        $(esc(a)), $(esc(b)), $(esc(c)), $(esc(d))
    end
end

@inline function store_u64!(x::AbstractVector{UInt32}, u::UInt64, idx)
    @inbounds begin
        x[idx] = UInt32(u & 0xffffffff)
        x[idx+1] = UInt32((u >> 32) & 0xffffffff)
    end
end

@inline function add_u64!(x::AbstractVector{UInt32}, u::UInt64, idx)
    @inbounds begin
        x[idx] += UInt32(u & 0xffffffff)
        x[idx+1] += UInt32((u >> 32) & 0xffffffff)
    end
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
    block_start = 1

    # We compute as many blocks of output as possible with 512-bit
    # SIMD vectorization
    for i ∈ 1:4:nblocks-3
        block_start, counter = _chacha_blocks!(
            buffer, block_start, key, nonce, counter, doublerounds, Val(4)
        )
    end

    # The remaining blocks are computed with 128-bit vectorization
    for i ∈ 1:(nblocks % 4)
        block_start, counter = _chacha_blocks!(
            buffer, block_start, key, nonce, counter, doublerounds, Val(1)
        )
    end

    counter
end

# Compute the ChaCha block function with N * 128-bit SIMD vectorization
#
# Reference: https://eprint.iacr.org/2013/759.pdf
@inline function _chacha_blocks!(
    buffer::AbstractVector{UInt32}, block_start, key, nonce, counter, doublerounds, ::Val{N}
) where N
    block_end = block_start + N * CHACHA_BLOCK_SIZE_U32 - 1
    @inbounds state = view(buffer, block_start:block_end)

    for i = 0:N-1
        _chacha_set_initial_state!(state, key, nonce, counter + i, i * CHACHA_BLOCK_SIZE_U32 + 1)
    end

    _chacha_rounds!(state, doublerounds, Val(N))

    for i = 0:N-1
        _chacha_add_initial_state!(state, key, nonce, counter + i, i * CHACHA_BLOCK_SIZE_U32 + 1)
    end

    block_end + 1, counter + N
end


@inline @generated function _chacha_rounds!(state, doublerounds, ::Val{N}) where N
    # Perform alternating rounds of columnar
    # quarter-rounds and diagonal quarter-rounds
    lane = (1, 2, 3, 4)
    lane = repeat(1:4, N)
    lane += 16 * ((0:4*N-1) .÷ 4)
    lane = Tuple(lane)

    idx0 = Vec(lane)
    idx1 = Vec(lane .+ 4)
    idx2 = Vec(lane .+ 8)
    idx3 = Vec(lane .+ 12)

    quote
        @inbounds begin
            v0 = vgather(state, $idx0)
            v1 = vgather(state, $idx1)
            v2 = vgather(state, $idx2)
            v3 = vgather(state, $idx3)

            for i = 1:doublerounds
                v0, v1, v2, v3 = @_QR!(v0, v1, v2, v3)
                v1 = rotatevector(v1, Val(-1))
                v2 = rotatevector(v2, Val(-2))
                v3 = rotatevector(v3, Val(-3))

                v0, v1, v2, v3 = @_QR!(v0, v1, v2, v3)
                v1 = rotatevector(v1, Val(1))
                v2 = rotatevector(v2, Val(2))
                v3 = rotatevector(v3, Val(3))
            end

            vscatter(v0, state, $idx0)
            vscatter(v1, state, $idx1)
            vscatter(v2, state, $idx2)
            vscatter(v3, state, $idx3)
        end
    end
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
    slice = view(state, block+1:block+16)

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
        @_QR!(slice[i], slice[i+4], slice[i+8], slice[i+12])
        CUDA.threadfence_block()

        # Diagonal rounds
        @_QR!(slice[dgc1], slice[dgc2], slice[dgc3], slice[dgc4])
        CUDA.threadfence_block()
    end

    nothing
end

export CHACHA_BLOCK_SIZE, CHACHA_BLOCK_SIZE_U32
export chacha_blocks!

end # module
