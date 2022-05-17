# API

```@meta
CurrentModule = ChaChaCiphers
```

## Keystream types

```@autodocs
Modules = [ChaChaCiphers]
Filter = t -> (t isa DataType && t <: ChaChaCiphers.AbstractChaChaStream) ||
  t in (ChaCha12Stream, ChaCha20Stream, CUDAChaCha12Stream, CUDAChaCha20Stream)
```

## Keystream helpers

```@autodocs
Modules = [ChaChaCiphers]
Filter = t -> t in (getstate, ChaChaCiphers.ChaChaState)
```

## Encryption and decryption

```@autodocs
Modules = [ChaChaCiphers]
Filter = t -> t in (encrypt!, decrypt!)
```

## Index

```@index
```
