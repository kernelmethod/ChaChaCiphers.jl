# Tests for random number generation with
# CUDAChaChaStream

using ChaChaCiphers
using CUDA
using Random
using Statistics
using Test

@testset "CUDAChaChaStream tests" begin
    if CUDA.functional()
        @testset "Construct CUDAChaChaStream" begin
            rng = CUDAChaCha12Stream()
            @test rng.doublerounds == 6

            rng = CUDAChaCha20Stream()
            @test rng.doublerounds == 10
        end

        @testset "Generate random strings" begin
            rng = CUDAChaChaStream(zeros(UInt32, 8), UInt64(0))
            x = randstring(rng, 'a':'c', 3 * 2^16)
            @test isa(x, String)
            @test length(x) == 3 * 2^16

            counts = Dict((c => count(u -> u == c, x)) for c ∈ 'a':'c')
            counts = Dict((c => counts[c] / length(x)) for c ∈ 'a':'c')
            @test isapprox(counts['a'], 1/3, atol=1e-2)
            @test isapprox(counts['b'], 1/3, atol=1e-2)
            @test isapprox(counts['c'], 1/3, atol=1e-2)
        end

        @testset "Sample uniform random numbers" begin
            rng = CUDAChaChaStream(zeros(UInt32, 8), UInt64(0))
            x = rand(rng, Float32, 100_000)

            @test isa(x, Vector{Float32})
            @test size(x) == (100_000,)
            @test isapprox(mean(x), 0.5, atol=1e-2)

            x = rand(rng, Float64, 400, 300)
            @test isa(x, Array{Float64,2})
            @test size(x) == (400, 300)
            @test isapprox(mean(x), 0.5, atol=1e-2)

            # Generate random values directly inside of a pre-allocated array
            x_cpu = Vector{Float32}(undef, 100_000)
            Random.rand!(rng, x_cpu)
            @test isapprox(mean(x_cpu), 0.5, atol=1e-2)

            x_cpu .= 0
            x_gpu = CuVector{Float32}(undef, 100_000)
            CUDA.@sync begin
                Random.rand!(rng, x_gpu)
                copyto!(x_cpu, x_gpu)
            end
            @test isapprox(mean(x_cpu), 0.5, atol=1e-2)
        end

        @testset "Sample random normal numbers" begin
            rng = CUDAChaChaStream(zeros(UInt32, 8), UInt64(0))
            x = randn(rng, Float32, 100_000)

            @test isa(x, Vector{Float32})
            @test size(x) == (100_000,)
            @test isapprox(mean(x), 0, atol=1e-2)
            @test isapprox(std(x), 1, atol=1e-2)

            x = randn(rng, Float64, 100, 50, 50)
            @test isa(x, Array{Float64,3})
            @test size(x) == (100, 50, 50)
            @test isapprox(mean(x), 0, atol=1e-2)
            @test isapprox(std(x), 1, atol=1e-2)
        end

        @testset "Save and restore keystream" begin
            # We should be able to save and restore a GPU
            # keystream as a CPU keystream, and vice-versa
            rng = CUDAChaChaStream(zeros(UInt32, 8), UInt64(0))
            state = getstate(rng)
            rng_cpu = ChaChaStream(state)

            rand_gpu = rand(rng, 1_000)
            rand_cpu = rand(rng_cpu, 1_000)

            @test rand_gpu == rand_cpu
        end
    else
        @warn "CUDA.functional() = false; skipping tests"
    end
end
