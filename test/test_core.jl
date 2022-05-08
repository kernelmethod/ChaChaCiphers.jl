using ChaChaCiphers: UnsafeView
using Test

@testset "UnsafeView tests" begin
    @testset "Construct UnsafeView over different arrays" begin
        x = UInt8.(1:100)
        GC.@preserve x begin
            view = UnsafeView(pointer(x), 10)

            # TODO: add bounds checking that can be
            # circumvented with @inbounds
            @test length(view) == 10
            @test view[1:10] == UInt8.(1:10)
        end

        x = UInt64.(1:100)
        GC.@preserve x begin
            view = UnsafeView(pointer(x), length(x))
            @test length(view) == 100
            @test length(view[50:60]) == 11
            @test view[50:60] == UInt64.(50:60)
        end
    end

    @testset "Get a view() of an UnsafeView" begin
        x = randn(Float64, 64)
        GC.@preserve x begin
            x_view = UnsafeView(pointer(x), length(x))
            x_subview = view(x_view, 1:10)
            @test length(x_subview) == 10
            @test x_subview == x[1:10]

            x_subview = view(x_view, 33:64)
            @test length(x_subview) == 32
            @test x_subview == x[33:64]
        end
    end
end
