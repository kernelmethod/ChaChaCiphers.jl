# ChaChaCiphers

[ChaChaCiphers](https://github.com/kernelmethod/ChaChaCiphers.jl) is a
CUDA-compatible, pure-Julia implementation of the ChaCha family of stream
ciphers. This package provides:

- fast, cryptographically-secure, and reproducible random number generators
  implementing Julia's `AbstractRNG` interface for both CPU and GPU, and
- implementations of ChaCha stream ciphers such as ChaCha20 that can be used as
  building blocks for other cryptographic primitives, such as ChaCha20-Poly1305.

!!! warning
    ChaCha is not sufficient by itself for encrypting data, and misuse can
    compromise application security. Please review [the warnings
    section](#warnings-and-disclaimers) for more details.

## Basic usage

```@meta
DocTestSetup = quote
  using ChaChaCiphers
  key = UInt32.([
    0xe2e39848, 0x70bb974d, 0x845f88b4, 0xb30725e4,
    0x15c309dc, 0x72d545bb, 0x466e99e3, 0x6a759f91
  ]);
  nonce = UInt64(0);
  rng = ChaCha20Stream(key, nonce);
end
```

To start generating random numbers with ChaChaCiphers, create a new keystream
with a function like [`ChaCha20Stream`](@ref) or [`ChaCha12Stream`](@ref):

```jldoctest
julia> using ChaChaCiphers

julia> rng = ChaCha20Stream();
```

This will generate a keystream using a key sampled from the operating system's
random stream. Alternatively,  you can explicitly specify a `key` and `nonce` as
follows:

```jldoctest
julia> key = UInt32.([
          0xe2e39848, 0x70bb974d, 0x845f88b4, 0xb30725e4,
          0x15c309dc, 0x72d545bb, 0x466e99e3, 0x6a759f91
       ]);

julia> nonce = UInt64(0);

julia> rng = ChaCha20Stream(key, nonce);
```

After generating a keystream, you can supply it as the `rng` parameter to
`Random` functions like `rand` and `randn`:

```jldoctest
julia> using Random

julia> rand(rng, 1:10)
3

julia> randn(rng, Float32, 3)
3-element Vector{Float32}:
 -0.50947624
 -0.9306026
 -0.084067896
```

Review the API documentation for more details.

## About ChaCha

ChaCha was first introduced as a variant of the Salsa20 stream cipher by Daniel
Bernstein in 2008[^Bernstein08]. ChaCha produces a stream of 512-bit blocks that
act as a CRNG seeded with a key and nonce.

ChaCha is used as the basis for the Linux kernel's CRNG[^LWN16]. It is one of
the two major components of the ChaCha20-Poly1305 Authenticated Encryption with
Associated Data (AEAD) algorithm specified by IETF RFC 8439[^RFC8439], which in
turn is used by [TLS](https://datatracker.ietf.org/doc/html/rfc7905),
[OpenSSH](http://bxr.su/OpenBSD/usr.bin/ssh/PROTOCOL.chacha20poly1305),
[Wireguard](https://www.wireguard.com/protocol/), and more.

ChaCha makes it easy to seek to any given portion of the keystream, which allows
extremely efficient parallel computation on CPU and GPU. It can also be computed
in constant time very efficiently in software, whereas comparable symmetric
ciphers (e.g. AES-CTR) require hardware support to achieve the same performance.

[^Bernstein08]:
    "ChaCha, a variant of Salsa20":
    [https://cr.yp.to/chacha/chacha-20080128.pdf](https://cr.yp.to/chacha/chacha-20080128.pdf)

[^LWN16]:
    "Replacing /dev/urandom":
    [https://lwn.net/Articles/686033/](https://lwn.net/Articles/686033/)

[^RFC8439]:
    [IETF RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)

## Warnings and disclaimers

### Security

ChaCha is not by itself sufficient to keep your data secure. In particular, it
doesn't provide any guarantees of data integrity or authenticity, and the
ciphertexts it produces are
[malleable](https://en.wikipedia.org/wiki/Malleability_%28cryptography%29_).

Most likely, if you are looking for an algorithm to encrypt your data, you'll
want an [AEAD algorithm](https://en.wikipedia.org/wiki/Authenticated_encryption)
such as [ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) or
[AES-GCM](https://datatracker.ietf.org/doc/html/rfc8452).

This package has not received a formal security analysis from an external party.
Please use with caution.

### Alternatives

If you don't strictly need a cryptographically secure random number generator,
you should consider using [Julia's built-in
RNG](https://docs.julialang.org/en/v1/stdlib/Random/), which as of v1.7 uses
[Xoshiro256++](https://prng.di.unimi.it/) and can easily beat ChaCha by an order
of magnitude or more in speed.

Alternatively, if you need a CRNG but don't care about reproducibility, you may
wish to consider using
[`RandomDevice`](https://docs.julialang.org/en/v1/stdlib/Random/#Random.RandomDevice)
from Julia's standard library, which pulls from the operating system's random
stream. In practice however [`ChaChaStream`](@ref) may be much faster than using
`RandomDevice`.
