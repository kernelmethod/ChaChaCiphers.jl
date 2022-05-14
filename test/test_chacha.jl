# Tests for ChaCha primitives
#
# The test vectors come from IETF RFC 8439:
# https://datatracker.ietf.org/doc/html/rfc8439#section-2.1.1
#
# Note that this module uses Daniel Bernstein's original construction
# of ChaCha, which uses a 64-bit nonce and a 64-bit counter. As a result
# the test vectors are slightly changed from RFC 8439.

using ChaChaCiphers.ChaCha
using CUDA
using StaticArrays
using Test

@testset "ChaCha tests" begin
    @testset "Quarter-round function tests" begin
        # Ref: IETF RFC 8439, Sec. 2.1.1
        # https://datatracker.ietf.org/doc/html/rfc8439#section-2.1.1
        state = MVector{4,UInt32}([0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567])
        ChaCha._QR!(state, 1, 2, 3, 4)

        expected_state = SVector{4,UInt32}([0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb])

        @test state == expected_state

        # Ref: IETF RFC 8439, Sec. 2.2.1
        # https://datatracker.ietf.org/doc/html/rfc8439#section-2.2.1

        state = MVector{16,UInt32}([
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
            0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
        ])
        initial_state = deepcopy(state)

        ChaCha._QR!(state, 3, 8, 9, 14)

        mask = trues(length(state))
        mask[3] = mask[8] = mask[9] = mask[14] = false

        @test state[mask] == initial_state[mask]
        @test state[@.(~mask)] == [
            0xbdb886dc, 0xcfacafd2, 0xe46bea80, 0xccc07c79
        ]
    end

    @testset "Test initial state" begin
        # Ref: IETF RFC 8439, Sec. 2.2.1
        # https://datatracker.ietf.org/doc/html/rfc8439#section-2.2.1
        key = SVector{8,UInt32}([
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ])
        nonce = 0x000000004a000000
        counter = 0x0900000000000001

        state_set = MVector{16,UInt32}(undef)
        state_add = MVector{16,UInt32}(zeros(UInt32, 16))
        ChaCha._chacha_set_initial_state!(state_set, key, nonce, counter)
        ChaCha._chacha_add_initial_state!(state_add, key, nonce, counter)
        test_vector = MVector{16,UInt32}([
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
            0x00000001, 0x09000000, 0x4a000000, 0x00000000,
        ])

        @test state_set == test_vector
        @test state_add == test_vector
    end

    @testset "Test chacha_blocks!" begin
        # Ref: IETF RFC 8439, Sec. 2.3.2
        # https://datatracker.ietf.org/doc/html/rfc8439#section-2.3.2
        key = SVector{8,UInt32}([
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        ])
        nonce = 0x000000004a000000
        counter = 0x0900000000000001

        test_vector = SVector{16,UInt32}([
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
            0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
            0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
            0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
        ])
        state = MVector{16,UInt32}(undef)
        @test ChaCha.chacha_blocks!(state, key, nonce, counter) == counter + 1
        @test state == test_vector

        # Ref: IETF RFC 8439, Appendix A.1
        # https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.1

        # Test Vector #1:
        # ==============
        key = SVector{8,UInt32}(zeros(UInt32, 8))
        nonce = UInt64(0)
        counter = UInt64(0)
        test_vector = SVector{16,UInt32}([
            0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653,
            0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,
            0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
            0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2
        ])
        state = MVector{16,UInt32}(undef)
        @test ChaCha.chacha_blocks!(state, key, nonce, counter) == counter + 1
        @test state == test_vector

        # Test Vector #2:
        # ==============
        key = SVector{8,UInt32}(zeros(UInt32, 8))
        nonce = UInt64(0)
        counter = UInt64(1)
        test_vector = SVector{16,UInt32}([
            0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73,
            0xa0290fcb, 0x6965e348, 0x3e53c612, 0xed7aee32,
            0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874,
            0x281fed31, 0x45fb0a51, 0x1f0ae1ac, 0x6f4d794b
        ])
        @test ChaCha.chacha_blocks!(state, key, nonce, counter) == counter + 1
        @test state == test_vector

        # Test Vector #3:
        # ==============
        key = SVector{8,UInt32}([
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x01000000,
        ])
        test_vector = SVector{16,UInt32}([
            0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1,
            0xe8252083, 0x60818b01, 0xf38422b8, 0x5aaa49c9,
            0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f,
            0x4436274e, 0x2561b3c8, 0xebdd4aa6, 0xa0136c00
        ])
        nonce = UInt64(0)
        counter = UInt64(1)
        @test ChaCha.chacha_blocks!(state, key, nonce, counter) == counter + 1
        @test state == test_vector

        # Test Vector #4:
        # ==============
        key = SVector{8,UInt32}([
            0x0000ff00, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000,
        ])
        nonce = UInt64(0)
        counter = UInt64(2)
        test_vector = SVector{16,UInt32}([
            0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394,
            0xa78dea8f, 0x5e269039, 0xa1bebbc1, 0xcaf09aae,
            0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6,
            0x546ca624, 0x1bec45d5, 0x87f47473, 0x96f0992e
        ])
        @test ChaCha.chacha_blocks!(state, key, nonce, counter) == counter + 1
        @test state == test_vector

        # Test Vector #5:
        # ==============
        key = SVector{8,UInt32}(zeros(UInt32, 8))
        nonce = UInt64(0x0200000000000000)
        counter = UInt64(0)
        test_vector = SVector{16,UInt32}([
            0x374dc6c2, 0x3736d58c, 0xb904e24a, 0xcd3f93ef,
            0x88228b1a, 0x96a4dfb3, 0x5b76ab72, 0xc727ee54,
            0x0e0e978a, 0xf3145c95, 0x1b748ea8, 0xf786c297,
            0x99c28f5f, 0x628314e8, 0x398a19fa, 0x6ded1b53
        ])
        @test ChaCha.chacha_blocks!(state, key, nonce, counter) == counter + 1
        @test state == test_vector
    end
end

@testset "CUDA ChaCha tests" begin
    @check_cuda begin
        @testset "Test quarter-round function" begin
            # Ref: IETF RFC 8439, Sec. 2.1.1
            # https://datatracker.ietf.org/doc/html/rfc8439#section-2.1.1
            state = MVector{4,UInt32}([0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567])

            state_gpu = CuArray(collect(repeat(state, 1024)))

            function kernel(state, a, b, c, d)
                i = 4 * (threadIdx().x - 1)
                ChaCha._QR!(state, i + a, i + b, i + c, i + d)
                nothing
            end

            ChaCha._QR!(state, 1, 2, 3, 4)
            CUDA.@sync @cuda threads=1024 kernel(state_gpu, 1, 2, 3, 4)

            @test state_gpu == CuArray(collect(repeat(state, 1024)))
        end

        @testset "Test chacha_blocks!" begin
            for _ = 1:64
                state = zeros(UInt32, 1024)
                state_gpu = CUDA.zeros(UInt32, 1024)
                key = SVector{8,UInt32}(rand(UInt32, 8))
                key_gpu = CuArray(key)
                nonce = rand(UInt64)
                counter = UInt64(0)

                ctr = chacha_blocks!(state, key, nonce, counter, 1024 ÷ 16)
                CUDA.@sync ctr_gpu = chacha_blocks!(state_gpu, key_gpu, nonce, counter, 1024 ÷ 16)

                @test ctr == ctr_gpu
                @test state_gpu == CuArray(state)
            end
        end
    end
end
