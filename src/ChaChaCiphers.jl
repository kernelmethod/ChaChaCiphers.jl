module ChaChaCiphers

include("ChaCha.jl")

include("core.jl")
include("keystream.jl")
include("generation.jl")

export ChaCha
export ChaChaStream, ChaCha20Stream, ChaCha12Stream
export getstate

end
