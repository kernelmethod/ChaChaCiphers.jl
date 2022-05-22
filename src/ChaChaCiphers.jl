module ChaChaCiphers

include("ChaCha.jl")

include("memory.jl")
include("core.jl")

include("keystream.jl")
include("cuda_keystream.jl")
include("generation.jl")

export ChaCha
export ChaChaStream, ChaCha20Stream, ChaCha12Stream
export CUDAChaChaStream, CUDAChaCha20Stream, CUDAChaCha12Stream
export getstate
export encrypt, decrypt, encrypt!, decrypt!

end
