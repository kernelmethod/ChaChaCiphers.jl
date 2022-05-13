using ChaChaCiphers.ChaCha: CHACHA_BLOCK_SIZE
using Random: AbstractRNG
using StaticArrays

### UnsafeView

struct UnsafeView{T} <: DenseArray{T,1}
    ptr :: Ptr{T}
    len :: Int
end

Base.length(a::UnsafeView) = a.len
Base.getindex(a::UnsafeView, i::Int) = unsafe_load(a.ptr, i)
Base.setindex!(a::UnsafeView, x, i::Int) = unsafe_store!(a.ptr, x, i)
Base.pointer(a::UnsafeView) = a.ptr
Base.size(a::UnsafeView) = (a.len,)
Base.elsize(::Type{UnsafeView{T}}) where {T} = sizeof(T)

function Base.view(a::UnsafeView{T}, i::UnitRange) where T
    ptr = a.ptr + sizeof(T) * (first(i) - 1)
    UnsafeView(ptr, length(i))
end

function Base.getindex(a::UnsafeView{T}, i::UnitRange) where T
    view_start = (first(i) - 1) * sizeof(T)
    len = length(i)
    UnsafeView(pointer(a) + view_start, len)
end

### ChaChaState

"""
    ChaChaState

A `NamedTuple` storing the current state of a ChaCha keystream. `ChaChaState`
can be used to save and restore the state of a keystream.
"""
const ChaChaState = @NamedTuple begin
    key :: SVector{8,UInt32}
    nonce :: UInt64
    counter :: UInt64
    position :: Int
    doublerounds :: Int
end


### AbstractChaChaStream

# Number of bytes to store in an AbstractChaChaStream
const STREAM_BUFFER_SIZE = CHACHA_BLOCK_SIZE

if STREAM_BUFFER_SIZE % CHACHA_BLOCK_SIZE != 0
    error("STREAM_BUFFER_SIZE must be a multiple of the CHACHA_BLOCK_SIZE")
end

const STREAM_BUFFER_BLOCKS = STREAM_BUFFER_SIZE ÷ CHACHA_BLOCK_SIZE

"""
    AbstractChaChaStream

Abstract parent type for ChaCha keystreams.
"""
abstract type AbstractChaChaStream <: AbstractRNG end

# Constructors

(::Type{T})(; kws...) where {T <: AbstractChaChaStream} =
    T(SVector{8,UInt32}(rand(RandomDevice(), UInt32, 8)); kws...)
(::Type{T})(key; kws...) where {T <: AbstractChaChaStream} =
    T(key, UInt64(0); kws...)
(::Type{T})(state::ChaChaState) where {T <: AbstractChaChaStream} =
    T(state.key, state.nonce, state.counter, state.position; doublerounds=state.doublerounds)

"""
    getstate(stream::AbstractChaChaStream)

Return a `NamedTuple` containing enough state of the input
`AbstractChaChaStream` to be able to reproduce it.
"""
function getstate(stream::AbstractChaChaStream)
    (;
        :key => key(stream),
        :nonce => nonce(stream),
        :counter => counter(stream) - STREAM_BUFFER_BLOCKS,
        :position => position(stream),
        :doublerounds => doublerounds(stream),
    )
end

Base.copy(stream::T) where {T <: AbstractChaChaStream} = T(getstate(stream))
