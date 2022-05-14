var documenterSearchIndex = {"docs":
[{"location":"api/#API","page":"API","title":"API","text":"","category":"section"},{"location":"api/","page":"API","title":"API","text":"","category":"page"},{"location":"api/","page":"API","title":"API","text":"CurrentModule = ChaChaCiphers","category":"page"},{"location":"api/","page":"API","title":"API","text":"Modules = [ChaChaCiphers]","category":"page"},{"location":"api/#ChaChaCiphers.AbstractChaChaStream","page":"API","title":"ChaChaCiphers.AbstractChaChaStream","text":"AbstractChaChaStream\n\nAbstract parent type for ChaCha keystreams.\n\n\n\n\n\n","category":"type"},{"location":"api/#ChaChaCiphers.CUDAChaChaStream","page":"API","title":"ChaChaCiphers.CUDAChaChaStream","text":"CUDAChaChaStream <: AbstractChaChaStream\n\nCUDAChaChaStream is a CUDA-compatible ChaCha keystream generator for GPU CRNG.\n\nExamples\n\nCreate a CUDAChaChaStream with a randomized key, and sample some random numbers with it:\n\nDocTestSetup = quote\n    using CUDA\n    using ChaChaCiphers\n    using Random\nend\n\njulia> rng = CUDAChaChaStream();\n\njulia> x = CuVector{Float32}(undef, 2^10);\n\nDocTestSetup = nothing\n\nSee also: ChaChaStream\n\n\n\n\n\n","category":"type"},{"location":"api/#ChaChaCiphers.ChaChaState","page":"API","title":"ChaChaCiphers.ChaChaState","text":"ChaChaState\n\nA NamedTuple storing the current state of a ChaCha keystream. ChaChaState can be used to save and restore the state of a keystream.\n\n\n\n\n\n","category":"type"},{"location":"api/#ChaChaCiphers.ChaChaStream","page":"API","title":"ChaChaCiphers.ChaChaStream","text":"ChaChaStream <: AbstractChaChaStream\n\nChaChaStream provides access to the keystream generated by the ChaCha stream cipher. It can be used as a cryptographically secure random number generator (CRNG) for Julia's random number generation functions.\n\nExamples\n\nCreate a ChaChaStream with a randomly-generated key and nonce:\n\nDocTestSetup = quote\n    using ChaChaCiphers\n    using Random\nend\n\njulia> stream = ChaCha20Stream();\n\nCreate a ChaChaStream with a pre-specified key and nonce, and use it to generate random data:\n\njulia> key = UInt32.([\n          0xe2e39848, 0x70bb974d, 0x845f88b4, 0xb30725e4,\n          0x15c309dc, 0x72d545bb, 0x466e99e3, 0x6a759f91\n       ]);\n\njulia> nonce = UInt64(1234);\n\njulia> stream = ChaCha20Stream(key, nonce);\n\njulia> randn(stream)\n0.7689072580509484\n\njulia> randstring(stream, 'a':'z', 8)\n\"klmptewr\"\n\nDocTestSetup = nothing\n\nSee also: CUDAChaChaStream\n\n\n\n\n\n","category":"type"},{"location":"api/#ChaChaCiphers.CUDAChaCha12Stream-Tuple","page":"API","title":"ChaChaCiphers.CUDAChaCha12Stream","text":"CUDAChaCha12Stream\n\nCreate a CUDA-compatible keystream for a ChaCha12 stream cipher.\n\n\n\n\n\n","category":"method"},{"location":"api/#ChaChaCiphers.CUDAChaCha20Stream-Tuple","page":"API","title":"ChaChaCiphers.CUDAChaCha20Stream","text":"CUDAChaCha20Stream\n\nCreate a CUDA-compatible keystream for a ChaCha20 stream cipher.\n\n\n\n\n\n","category":"method"},{"location":"api/#ChaChaCiphers.ChaCha12Stream-Tuple","page":"API","title":"ChaChaCiphers.ChaCha12Stream","text":"ChaCha12Stream(args...)\n\nCreate a keystream for a ChaCha12 stream cipher.\n\n\n\n\n\n","category":"method"},{"location":"api/#ChaChaCiphers.ChaCha20Stream-Tuple","page":"API","title":"ChaChaCiphers.ChaCha20Stream","text":"ChaCha20Stream(args...)\n\nCreate a keystream for a ChaCha20 stream cipher.\n\n\n\n\n\n","category":"method"},{"location":"api/#ChaChaCiphers.decrypt!-Tuple{ChaChaStream, Any}","page":"API","title":"ChaChaCiphers.decrypt!","text":"decrypt(stream::ChaChaStream, x)\ndecrypt!(stream::ChaChaStream, x)\n\nDecrypt an encrypted vector x using the keystream from a ChaChaStream.\n\n\n\n\n\n","category":"method"},{"location":"api/#ChaChaCiphers.encrypt!-Union{Tuple{T}, Tuple{ChaChaStream, DenseVector{T}}} where T<:Union{Int128, Int16, Int32, Int64, Int8, UInt128, UInt16, UInt32, UInt64, UInt8}","page":"API","title":"ChaChaCiphers.encrypt!","text":"encrypt(stream::ChaChaStream, x)\nencrypt!(stream::ChaChaStream, x)\n\nEncrypt a vector or string x using the keystream from a ChaChaStream.\n\n\n\n\n\n","category":"method"},{"location":"api/#ChaChaCiphers.getstate-Tuple{ChaChaCiphers.AbstractChaChaStream}","page":"API","title":"ChaChaCiphers.getstate","text":"getstate(stream::AbstractChaChaStream)\n\nReturn a NamedTuple containing enough state of the input AbstractChaChaStream to be able to reproduce it.\n\n\n\n\n\n","category":"method"},{"location":"#ChaChaCiphers","page":"Home","title":"ChaChaCiphers","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"ChaChaCiphers is a CUDA-compatible, pure-Julia implementation of the ChaCha family of stream ciphers. This package provides:","category":"page"},{"location":"","page":"Home","title":"Home","text":"fast, cryptographically-secure, and reproducible random number generators implementing Julia's AbstractRNG interface for both CPU and GPU, and\nimplementations of ChaCha stream ciphers such as ChaCha20 that can be used as building blocks for other cryptographic primitives, such as ChaCha20-Poly1305.","category":"page"},{"location":"","page":"Home","title":"Home","text":"warning: Warning\nChaCha is not sufficient by itself for encrypting data, and misuse can compromise application security. Please review the warnings section for more details.","category":"page"},{"location":"#Basic-usage","page":"Home","title":"Basic usage","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"DocTestSetup = quote\n  using ChaChaCiphers\n  key = UInt32.([\n    0xe2e39848, 0x70bb974d, 0x845f88b4, 0xb30725e4,\n    0x15c309dc, 0x72d545bb, 0x466e99e3, 0x6a759f91\n  ]);\n  nonce = UInt64(0);\n  rng = ChaCha20Stream(key, nonce);\nend","category":"page"},{"location":"","page":"Home","title":"Home","text":"To start generating random numbers with ChaChaCiphers, create a new keystream with a function like ChaCha20Stream or ChaCha12Stream:","category":"page"},{"location":"","page":"Home","title":"Home","text":"julia> using ChaChaCiphers\n\njulia> rng = ChaCha20Stream();","category":"page"},{"location":"","page":"Home","title":"Home","text":"This will generate a keystream using a key sampled from the operating system's random stream. Alternatively,  you can explicitly specify a key and nonce as follows:","category":"page"},{"location":"","page":"Home","title":"Home","text":"julia> key = UInt32.([\n          0xe2e39848, 0x70bb974d, 0x845f88b4, 0xb30725e4,\n          0x15c309dc, 0x72d545bb, 0x466e99e3, 0x6a759f91\n       ]);\n\njulia> nonce = UInt64(0);\n\njulia> rng = ChaCha20Stream(key, nonce);","category":"page"},{"location":"","page":"Home","title":"Home","text":"After generating a keystream, you can supply it as the rng parameter to Random functions like rand and randn:","category":"page"},{"location":"","page":"Home","title":"Home","text":"julia> using Random\n\njulia> rand(rng, 1:10)\n3\n\njulia> randn(rng, Float32, 3)\n3-element Vector{Float32}:\n -0.50947624\n -0.9306026\n -0.084067896","category":"page"},{"location":"","page":"Home","title":"Home","text":"Review the API documentation for more details.","category":"page"},{"location":"#About-ChaCha","page":"Home","title":"About ChaCha","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"ChaCha was first introduced as a variant of the Salsa20 stream cipher by Daniel Bernstein in 2008[Bernstein08]. ChaCha produces a stream of 512-bit blocks that act as a CRNG seeded with a key and nonce.","category":"page"},{"location":"","page":"Home","title":"Home","text":"ChaCha is used as the basis for the Linux kernel's CRNG[LWN16]. It is one of the two major components of the ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) algorithm specified by IETF RFC 8439[RFC8439], which in turn is used by TLS, OpenSSH, Wireguard, and more.","category":"page"},{"location":"","page":"Home","title":"Home","text":"ChaCha makes it easy to seek to any given portion of the keystream, which allows extremely efficient parallel computation on CPU and GPU. It can also be computed in constant time very efficiently in software, whereas comparable symmetric ciphers (e.g. AES-CTR) require hardware support to achieve the same performance.","category":"page"},{"location":"","page":"Home","title":"Home","text":"[Bernstein08]: \"ChaCha, a variant of Salsa20\": https://cr.yp.to/chacha/chacha-20080128.pdf","category":"page"},{"location":"","page":"Home","title":"Home","text":"[LWN16]: \"Replacing /dev/urandom\": https://lwn.net/Articles/686033/","category":"page"},{"location":"","page":"Home","title":"Home","text":"[RFC8439]: IETF RFC 8439","category":"page"},{"location":"#Warnings-and-disclaimers","page":"Home","title":"Warnings and disclaimers","text":"","category":"section"},{"location":"#Security","page":"Home","title":"Security","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"ChaCha is not by itself sufficient to keep your data secure. In particular, it doesn't provide any guarantees of data integrity or authenticity, and the ciphertexts it produces are malleable.","category":"page"},{"location":"","page":"Home","title":"Home","text":"Most likely, if you are looking for an algorithm to encrypt your data, you'll want an AEAD algorithm such as ChaCha20-Poly1305 or AES-GCM.","category":"page"},{"location":"","page":"Home","title":"Home","text":"This package has not received a formal security analysis from an external party. Please use with caution.","category":"page"},{"location":"#Alternatives","page":"Home","title":"Alternatives","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"If you don't strictly need a cryptographically secure random number generator, you should consider using Julia's built-in RNG, which as of v1.7 uses Xoshiro256++ and can easily beat ChaCha by an order of magnitude or more in speed.","category":"page"},{"location":"","page":"Home","title":"Home","text":"Alternatively, if you need a CRNG but don't care about reproducibility, you may wish to consider using RandomDevice from Julia's standard library, which pulls from the operating system's random stream. In practice however ChaChaStream may be much faster than using RandomDevice.","category":"page"}]
}
