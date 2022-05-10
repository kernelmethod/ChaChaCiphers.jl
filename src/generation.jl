#=

Implementation of the RNG API for ChaChaStream

=#

using Random
using Random: SamplerType

Random.rng_native_52(::ChaChaStream) = UInt64

Random.rand(rng::ChaChaStream, ::Type{T}) where {T <: BitInteger} =
    _fetch_one!(rng, T)

Random.rand(rng::ChaChaStream, T::Random.SamplerType{<:BitInteger}) =
    _fetch_one!(rng, T[])

Random.rand!(rng::ChaChaStream, A::Array) = Random.rand!(rng, A, eltype(A))

function Random.rand!(rng::ChaChaStream, A::Array{T}, ::SamplerType{T}) where {T <: BitInteger}
    Random.rand!(rng, vec(A), T)
    A
end

function Random.rand!(rng::ChaChaStream, A::Vector{T}, ::SamplerType{T}) where {T <: BitInteger}
    # Reinterpret the array as a byte array
    @GC.preserve A begin
        p = pointer(A)
        p = Base.unsafe_convert(Ptr{UInt8}, p)
        buf = unsafe_wrap(Vector{UInt8}, p, length(A) * sizeof(T), own=false)

        _fill_buffer!(buf, rng)
    end

    A
end


