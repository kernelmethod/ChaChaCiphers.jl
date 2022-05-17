#=

Implementation of the RNG API for ChaChaStream

=#

using CUDA
using Random
using Random: SamplerType

#=
RNG methods for all subtypes of AbstractChaChaStream
=#

Random.rng_native_52(::AbstractChaChaStream) = UInt64

# Support for different dimension specifications
Random.rand(rng::AbstractChaChaStream, T::Type{<:BitInteger}) =
    Random.rand(rng, T, 1)[]
Random.rand(rng::AbstractChaChaStream, T::Type{<:BitInteger}, dim1::Int, dims::Int...) =
    Random.rand(rng, T, Dims((dim1, dims...)))
Random.rand(rng::AbstractChaChaStream, T::Type{<:BitInteger}, dims::Dims) =
    Random.rand!(rng, Array{T}(undef, dims))

# Inplace operations
Random.rand!(rng::AbstractChaChaStream, A::AbstractArray{<:BitInteger}) =
    Random.rand!(rng, A, eltype(A))
Random.rand!(rng::AbstractChaChaStream, A::CuArray{<:BitInteger}) =
    Random.rand!(rng, A, eltype(A))

Random.rand!(
    rng::AbstractChaChaStream,
    A::Array{T},
    ::Type{T},
) where {T <: BitInteger} =
    (Random.rand!(rng, vec(A), T); A)

#=
RNG methods for ChaChaStream
=#

Random.rand(rng::ChaChaStream, ::Type{T}) where {T <: BitInteger} =
    _fetch_one!(rng, T)

Random.rand(rng::ChaChaStream, T::Random.SamplerType{<:BitInteger}) =
    _fetch_one!(rng, T[])

# Inplace operations
function Random.rand!(rng::ChaChaStream, A::Vector{T}, ::Type{T}) where {T <: BitInteger}
    # Reinterpret the array as a byte array
    @GC.preserve A begin
        p = pointer(A)
        p = Base.unsafe_convert(Ptr{UInt8}, p)
        buf = unsafe_wrap(Vector{UInt8}, p, sizeof(A), own=false)

        _fill_buffer!(buf, rng)
    end

    A
end

#=
RNG methods for CUDAChaChaStream
=#

function Random.rand!(rng::CUDAChaChaStream, A::Vector{T}, ::Type{T}) where {T <: BitInteger}
    # Perform sampling on GPU and then copy to CPU
    A_gpu = CuVector{T}(undef, length(A))
    Random.rand!(rng, A_gpu, T)
    copyto!(A, A_gpu)
end

Random.rand!(
    rng::CUDAChaChaStream,
    A::CuVector{T},
    ::Type{T}
) where {T <: BitInteger} =
    (_fill_buffer!(reinterpret(UInt8, A), rng); A)

