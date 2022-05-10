using Base: BitInteger
using StaticArrays

using ChaChaCiphers.ChaCha

"""
    ChaChaStream

A cryptographically secure pseudo-random number generator
(CRNG) based on the ChaCha stream cipher.
"""
mutable struct ChaChaStream <: AbstractChaChaStream
    key :: SVector{8,UInt32}
    nonce :: UInt64
    counter :: UInt64
    buffer :: MVector{STREAM_BUFFER_SIZE,UInt8}
    position :: Int
    doublerounds :: Int

    function ChaChaStream(
        key,
        nonce,
        counter = UInt64(0),
        position = 1;
        doublerounds = 10
    )
        if doublerounds < 0 || !iseven(doublerounds)
            error("`doublerounds` must be an even positive number")
        end

        key = SVector{8,UInt32}(key)
        buffer = MVector{STREAM_BUFFER_SIZE,UInt8}(undef)
        stream = new(key, nonce, counter, buffer, 1, doublerounds)
        _refresh_buffer!(stream)
        stream.position = position

        stream
    end
end

# Constructors
ChaCha20Stream(args...) = ChaChaStream(args...; doublerounds=10)
ChaCha12Stream(args...) = ChaChaStream(args...; doublerounds=6)

Base.show(io::IO, rng::ChaChaStream) =
    write(io, "ChaChaStream(key=$(rng.key), nonce=$(rng.nonce), counter=$(rng.counter))")

buffer_size(stream::ChaChaStream) = length(stream.buffer) - stream.position + 1

# Accessors; must be defined for AbstractChaChaStream.

key(stream::ChaChaStream) = stream.key
nonce(stream::ChaChaStream) = stream.nonce
counter(stream::ChaChaStream) = stream.counter
position(stream::ChaChaStream) = stream.position
doublerounds(stream::ChaChaStream) = stream.doublerounds

function _refresh_buffer!(stream::ChaChaStream)
    _fill_blocks!(
        stream.buffer,
        stream,
        STREAM_BUFFER_BLOCKS
    )
    stream.position = 1
    stream
end

# Fill a buffer with a block of the keystream
function _fill_blocks!(
    buffer::AbstractVector{T}, stream::ChaChaStream, nblocks::Int
) where {T <: BitInteger}
    bufsize_u32 = div(length(buffer) * sizeof(T), sizeof(UInt32))

    GC.@preserve buffer begin
        # Create a pointer to the start of the block,
        # and wrap it in an instance of UnsafeView.
        #
        # This provides a decent speedup over using
        # reinterpret(UInt32, ...)
        bp = pointer(buffer)
        bp = Base.unsafe_convert(Ptr{UInt32}, bp)
        bufview = UnsafeView(bp, bufsize_u32)

        stream.counter = chacha_blocks!(
            bufview,
            stream.key,
            stream.nonce,
            stream.counter,
            nblocks
        )
    end

    buffer
end

# Fetch bytes from the ChaChaStream buffer and increment the position index
function _fetch_one!(stream::ChaChaStream, ::Type{T}) where {T <: BitInteger}
    if buffer_size(stream) < sizeof(T)
        _refresh_buffer!(stream)
    end

    buffer = stream.buffer

    val = GC.@preserve buffer begin
        p = pointer(buffer, stream.position)
        p = Base.unsafe_convert(Ptr{T}, p)
        unsafe_load(p)
    end

    stream.position += sizeof(T)
    val
end

function _fill_buffer!(dest::AbstractVector{UInt8}, stream::ChaChaStream)
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

    # Instead of repeatedly operating on the stream buffer, we insert
    # as many blocks of the keystream into the destination as possible
    (n_blocks, rem) = divrem(length(dest) - bfsize, CHACHA_BLOCK_SIZE)
    GC.@preserve dest begin
        sp = pointer(dest, bfsize + 1)
        slice = unsafe_wrap(Vector{UInt8}, sp, n_blocks * CHACHA_BLOCK_SIZE, own=false)
        _fill_blocks!(slice, stream, n_blocks)
    end

    # Refresh the stream, and then copy the stream buffer into the
    # remainder of the destination
    _refresh_buffer!(stream)
    _fill_buffer!(view(dest, length(dest)-rem+1:length(dest)), stream)

    dest
end

#=
Stream cipher methods
=#

"""
    decrypt(stream::ChaChaStream, x)
    decrypt!(stream::ChaChaStream, x)

Decrypt an encrypted vector `x` using the keystream from a [`ChaChaStream`](@ref).
"""
decrypt!(stream::ChaChaStream, x) = encrypt!(stream, x)
decrypt(stream::ChaChaStream, x) = decrypt!(stream, copy(x))
decrypt(stream::ChaChaStream, x::AbstractString) = decrypt!(stream, collect(codeunits(x)))

"""
    encrypt(stream::ChaChaStream, x)
    encrypt!(stream::ChaChaStream, x)

Encrypt a vector or string `x` using the keystream from a [`ChaChaStream`](@ref).
"""
encrypt!(stream::ChaChaStream, x::DenseVector{T}) where {T <: BitInteger} =
    map!(u -> u ⊻ _fetch_one!(stream, T), x, x)
encrypt(stream::ChaChaStream, x) = encrypt!(stream, copy(x))
encrypt(stream::ChaChaStream, x::AbstractString) = encrypt!(stream, collect(codeunits(x)))
