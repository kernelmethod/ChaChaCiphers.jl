# Benchmarking for ChaCha routines

using BenchmarkTools
using CUDA
using ChaChaCiphers.ChaCha
using StaticArrays

const N = 2^25

@info "Running benchmarks with N = $N"
@info "Benchmarking chacha_block! for CPU"

const x = zeros(UInt32, N)
const key = SVector{8,UInt32}(rand(UInt32, 8))
const nonce = rand(UInt64)
const counter = UInt64(0)

# Warm up and benchmark
chacha_blocks!(x, key, nonce, counter, length(x) ÷ 16)
display(@benchmark chacha_blocks!(x, key, nonce, counter, N ÷ 16))
println()

if CUDA.functional()
    @info "Benchmarking chacha_block! for GPU"

    const x_gpu = CUDA.zeros(UInt32, N)
    const key_gpu = CUDA.CuVector(rand(UInt32, 8))


    # Warm up and benchmark
    CUDA.@sync chacha_blocks!(x_gpu, key_gpu, nonce, counter, N ÷ 16)
    display(@benchmark CUDA.@sync chacha_blocks!(x_gpu, key_gpu, nonce, counter, N ÷ 16))
    println()
else
    @warn "Unable to run CUDA benchmarks"
end

