# Testing utilities

macro check_cuda(expr)
    quote
        import CUDA

        if CUDA.functional()
            $(esc(expr))
        else
            @warn "CUDA.functional() = false; skipping tests"
        end
    end
end
