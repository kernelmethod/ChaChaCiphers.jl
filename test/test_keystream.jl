# Tests for random number generation with ChaChaStream

using ChaChaCiphers
using Random
using Statistics
using Test

@testset "ChaChaStream random number generation tests" begin
    @testset "Sample random numbers from a collection" begin
        stream = ChaCha12Stream(zeros(8), 0)
        samples = rand(stream, Int(0):Int(1), 65536)
        @test isa(samples, Vector{Int})
        @test length(samples) == 65536
        @test isapprox(mean(samples), 0.5, atol=1e-2)
        @test all(map(x -> x ∈ Int(0):Int(1), samples))

        samples = rand(stream, ('a', 'b', 'c'), 333333)
        @test isa(samples, Vector{Char})
        @test length(samples) == 333333
        counts = Dict((c => count(x -> x == c, samples)) for c ∈ ('a', 'b', 'c'))
        counts = Dict((c => counts[c] / length(samples)) for c ∈ ('a', 'b', 'c'))
        @test isapprox(counts['a'], 1/3, atol=1e-2)
        @test isapprox(counts['b'], 1/3, atol=1e-2)
        @test isapprox(counts['c'], 1/3, atol=1e-2)
    end

    @testset "Generate uniform distribution on [0,1]" begin
        stream = ChaCha12Stream(zeros(8), 0)
        samples = rand(stream, Float32, (100_000,))
        @test isa(samples, Vector{Float32})
        @test length(samples) == 100_000
        @test isapprox(mean(samples), 0.5, atol=1e-2)
    end

    @testset "Generate normal distribution with μ = 0, σ = 1" begin
        stream = ChaCha12Stream(zeros(8), 0)
        samples = randn(stream, Float32, (100_000,))
        @test isa(samples, Vector{Float32})
        @test length(samples) == 100_000
        @test isapprox(mean(samples), 0., atol=1e-2)
        @test isapprox(std(samples), 1., atol=1e-2)

        samples = randn(stream, Float64, (100_000,))
        @test isa(samples, Vector{Float64})
        @test length(samples) == 100_000
        @test isapprox(mean(samples), 0., atol=1e-2)
        @test isapprox(std(samples), 1., atol=1e-2)
    end

    @testset "Save and restore a keystream" begin
        # Create a stream, run some operations on it,
        # and save its state. Ensure that we can
        # reproduce the stream from its saved state.
        stream = ChaCha12Stream()
        rand(stream, UInt8, 3_000)
        stream_repro = getstate(stream) |> ChaChaStream

        rand_orig = randn(stream, 5_000)
        rand_repro = randn(stream_repro, 5_000)
        @test rand_orig == rand_repro

        stream = ChaCha20Stream()
        randn(stream, Float64, 3_000)
        stream_repro = getstate(stream) |> ChaChaStream

        rand_orig = rand(stream, 1:10, 1024)
        rand_repro = rand(stream_repro, 1:10, 1024)
        @test rand_orig == rand_repro
    end
end

