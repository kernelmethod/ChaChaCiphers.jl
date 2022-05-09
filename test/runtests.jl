using ChaChaCiphers, Documenter, Test

include("test_core.jl")
include("test_chacha.jl")
include("test_keystream.jl")

@testset "Package doctests" begin
    doctest(ChaChaCiphers; manual=false)
end
