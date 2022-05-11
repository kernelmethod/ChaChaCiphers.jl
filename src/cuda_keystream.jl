using Base: BitInteger
using ChaChaCiphers.ChaCha
using CUDA
using StaticArrays

"""
    CUDAChaChaStream <: AbstractChaChaStream

`CUDAChaChaStream` is a CUDA-compatible ChaCha keystream
generator for GPU CRNG.

## Examples

Create a `CUDAChaChaStream` with a randomized key, and
sample some random numbers with it:

```@meta
DocTestSetup = quote
    using CUDA
    using ChaChaCiphers
    using Random
end
```

```julia
julia> rng = CUDAChaChaStream();

julia> x = CuVector{Float32}(undef, 2^10);
```

```@meta
DocTestSetup = nothing
```

"""
mutable struct CUDAChaChaStream <: AbstractChaChaStream
    key :: CuVector{UInt32}
    nonce :: UInt64
    counter :: UInt64
    buffer :: CuVector{UInt8}
    position :: Int
    doublerounds :: Int

    function CUDAChaChaStream(
        key,
        nonce,
        counter = UInt64(0),
        position = 1;
        doublerounds = 10
    )
        if doublerounds ≤ 0
            error("`doublerounds` must be a positive number")
        end

        key = CuVector{UInt32}(key)
        buffer = CuVector{UInt8}(undef, STREAM_BUFFER_SIZE)
        stream = new(key, nonce, counter, buffer, 1, doublerounds)
        _refresh_buffer!(stream)
        stream.position = position

        stream
    end
end

# Constructors

"""
    CUDAChaCha20Stream

Create a CUDA-compatible keystream for a ChaCha20 stream
cipher.
"""
CUDAChaCha20Stream(args...) = CUDAChaChaStream(args...; doublerounds=10)

"""
    CUDAChaCha12Stream

Create a CUDA-compatible keystream for a ChaCha12 stream
cipher.
"""
CUDAChaCha12Stream(args...) = CUDAChaChaStream(args...; doublerounds=6)

function Base.show(io::IO, rng::CUDAChaChaStream)
    msg = """
        CUDAChaChaStream(
            key = $(key(rng))
            nonce = $(nonce(rng)),
            counter = $(counter(rng)),
            rounds = $(2 * doublerounds(rng))
        )"""

    write(io, msg)
end

buffer_size(stream::CUDAChaChaStream) =
    length(stream.buffer) - stream.position + 1

# Methods required for AbstractChaChaStream compatibility

function key(stream::CUDAChaChaStream)
    key_cpu = Vector{UInt32}(undef, 8)
    copyto!(key_cpu, stream.key)
    SVector{8,UInt32}(key_cpu)
end

@inline nonce(stream::CUDAChaChaStream) = stream.nonce
@inline counter(stream::CUDAChaChaStream) = stream.counter
@inline position(stream::CUDAChaChaStream) = stream.position
@inline doublerounds(stream::CUDAChaChaStream) = stream.doublerounds

function _refresh_buffer!(stream::CUDAChaChaStream)
    _fill_blocks!(
        stream.buffer,
        stream,
        STREAM_BUFFER_BLOCKS
    )
    stream.position = 1
    stream
end

function _fill_buffer!(dest::CuVector{UInt8}, stream::CUDAChaChaStream)
    bfsize = buffer_size(stream)
    destsize = length(dest)

    # If the internal buffer is larger than the destination size,
    # we can just copy directly from the buffer to the stream and
    # return
    if bfsize >= destsize
        copyto!(dest, 1, stream.buffer, stream.position, destsize)
        stream.position += destsize
        return dest
    end

    # Otherwise, the destination is larger than the buffer
    copyto!(dest, 1, stream.buffer, stream.position, bfsize)

    (n_blocks, rem) = divrem(length(dest) - bfsize, CHACHA_BLOCK_SIZE)
    if n_blocks > 0
        sp = pointer(dest, bfsize + 1)
        slice = unsafe_wrap(CuVector{UInt8}, sp, n_blocks * CHACHA_BLOCK_SIZE)
        _fill_blocks!(slice, stream, n_blocks)
    end

    # Refresh the stream, and then copy the stream buffer into the
    # remainder of the destination
    _refresh_buffer!(stream)
    _fill_buffer!(view(dest, length(dest)-rem+1:length(dest)), stream)

    dest
end

function _fill_blocks!(
    buffer::CuVector{T}, stream::CUDAChaChaStream, nblocks::Int
) where {T <: BitInteger}

    p = pointer(buffer)
    p = Base.unsafe_convert(CuPtr{UInt32}, p)
    buffer_u32 = unsafe_wrap(CuVector{UInt32}, p, nblocks * CHACHA_BLOCK_SIZE_U32)

    stream.counter = chacha_blocks!(
        buffer_u32,
        stream.key,
        stream.nonce,
        stream.counter,
        nblocks
    )

    buffer
end

