using ChaChaCiphers: SecretArray, SecretArray!
using StaticArrays
using Test

@testset "SecretArray tests" begin
    @testset "Wrap and zero out a Array" begin
        # Wrap a Array in a SecretArray to ensure
        # that its contents are zeroed out after
        # garbage collection

        x = ones(UInt32, 10)
        vec_b = vec_a = SecretArray(x)
        @test vec_a isa AbstractArray{UInt32}
        @test size(vec_a) == (10,)
        @test length(vec_a) == 10
        @test eltype(vec_a) == UInt32
        @test all(vec_a .== x)

        vec_a = nothing
        GC.gc()
        @test all(x .== 1)

        finalize(vec_b)
        @test all(x .== 0)

        vec_b = nothing
        GC.gc()
    end

    @testset "Wrap and zero out an MVector" begin
        x = MVector{32,UInt8}(ones(UInt8, 32))
        vec_b = vec_a = SecretArray(x)
        @test eltype(vec_a) == UInt8

        vec_a = nothing
        GC.gc()
        @test all(x .== 1)

        finalize(vec_b)
        @test all(x .== 0)

        vec_b = nothing
        GC.gc()
    end

    @testset "Wrap an array with SecretArray!" begin
        x = rand(UInt32, 8)
        x_copy = deepcopy(x)
        wrapper = SecretArray!(x)

        @test all(x .== 0)
        @test wrapper == x_copy
    end
end


