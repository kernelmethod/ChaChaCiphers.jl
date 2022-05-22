#=

Utilities for ensuring memory security.

=#

"""
    SecretArray

`SecretArray` is a wrapper around an array that zeros
out its contents before being garbage-collected.

This wrapper is analagous to the standard library's
`Base.SecretBuffer` but for arrays.
"""
mutable struct SecretArray{T, N, A <: AbstractArray{T,N}} <: AbstractArray{T,N}
    data :: A

    # Constructors
    function SecretArray(data::AbstractArray{T,N}) where {T,N}
        buffer = new{T,N,typeof(data)}(data)
        finalizer(final_shred!, buffer)
    end
end

const SecretVector{T, A} = SecretArray{T, 1, A} where {T, A}

"""
    SecretArray!(data::AbstractArray)

Construct a new `SecretArray` from `data`, and erase the contents
of `data`.
"""
SecretArray!(data::AbstractArray) = SecretArray!(data, similar(data))

function SecretArray!(data::AbstractArray, x)
    copyto!(x, data)
    Base.securezero!(data)
    SecretArray(x)
end

Base.eachindex(x::SecretArray) = eachindex(x.data)
Base.size(x::SecretArray) = size(x.data)
Base.length(x::SecretArray) = length(x.data)
Base.@propagate_inbounds Base.getindex(x::SecretArray, i) = getindex(x.data, i)
Base.@propagate_inbounds Base.setindex!(x::SecretArray, i) = setindex!(x.data, i)

Base.pointer(x::SecretArray) = pointer(x.data)
Base.pointer(x::SecretArray, i::Int) = pointer(x.data, i)

Base.eltype(::Type{SecretArray{T,N,A}}) where {T,N,A} = Base.eltype(A)
Base.elsize(::Type{SecretArray{T,N,A}}) where {T,N,A} = Base.elsize(A)
Base.similar(x::SecretArray) = SecretArray(similar(x.data))


Base.show(io::IO, buffer::SecretArray) =
    write(io, "SecretArray(\"*****\")")

final_shred!(x::SecretArray) = Base.shred!(x)

function Base.shred!(x::SecretArray)
    Base.securezero!(x.data)
    x
end

