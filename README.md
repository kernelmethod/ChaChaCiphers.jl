# ChaChaCiphers

[![Stable](https://img.shields.io/badge/docs-stable-blue.svg)](https://kernelmethod.github.io/ChaChaCiphers.jl/stable)
[![Dev](https://img.shields.io/badge/docs-dev-blue.svg)](https://kernelmethod.github.io/ChaChaCiphers.jl/dev)
[![Build Status](https://github.com/kernelmethod/ChaChaCiphers.jl/actions/workflows/CI.yml/badge.svg?branch=main)](https://github.com/kernelmethod/ChaChaCiphers.jl/actions/workflows/CI.yml?query=branch%3Amain)
[![Coverage](https://codecov.io/gh/kernelmethod/ChaChaCiphers.jl/branch/main/graph/badge.svg)](https://codecov.io/gh/kernelmethod/ChaChaCiphers.jl)

[ChaChaCiphers](https://github.com/kernelmethod/ChaChaCiphers.jl) is a
CUDA-compatible, pure-Julia implementation of the ChaCha family of stream
ciphers. This package provides:

- fast, cryptographically-secure, and reproducible random number generators
  implementing Julia's `AbstractRNG` interface for both CPU and GPU, and
- implementations of ChaCha stream ciphers such as ChaCha20 that can be used as
  building blocks for other cryptographic primitives, such as the
  ChaCha20-Poly1305 AEAD algorithm.

The default stream cipher provided by this package follows [Daniel Bernstein's
original implementation](https://cr.yp.to/chacha.html) (using a 64-bit counter
and 64-bit nonce), which allows you to generate 1 ZiB of random data before the
nonce must be recycled.

## Usage

You can start using ChaChaCiphers.jl for random number generation by creating a
`ChaChaStream` instance:

```julia
julia> using ChaChaCiphers

julia> rng = ChaChaStream();
```

This will create a `ChaChaStream` with a randomly-generated key. Alternatively,
you can specify a key and pass it in to `ChaChaStream` to create a reproducible
random number stream

```julia
julia> key = UInt32.([
          0xe2e39848, 0x70bb974d, 0x845f88b4, 0xb30725e4,
          0x15c309dc, 0x72d545bb, 0x466e99e3, 0x6a759f91
       ]);

julia> rng = ChaChaStream(key);
```

You can then pass `rng` into random number generation functions like `rand` or
`randn`:

```julia
julia> rand(rng, UInt8)
0x18

julia> rand(rng, 1:10, 3)
3-element Vector{Int64}:
 8
 4
 3

julia> randn(rng, 3)
3-element Vector{Float64}:
  0.4899558093907058
 -0.4164526650672216
 -0.864497576500388
```

