using ChaChaCiphers
using Documenter

DocMeta.setdocmeta!(ChaChaCiphers, :DocTestSetup, :(using ChaChaCiphers); recursive=true)

makedocs(;
    modules=[ChaChaCiphers],
    authors="kernelmethod <17100608+kernelmethod@users.noreply.github.com> and contributors",
    repo="https://github.com/kernelmethod/ChaChaCiphers.jl/blob/{commit}{path}#{line}",
    sitename="ChaChaCiphers.jl",
    format=Documenter.HTML(;
        prettyurls=get(ENV, "CI", "false") == "true",
        canonical="https://kernelmethod.github.io/ChaChaCiphers.jl",
        assets=String[],
    ),
    pages=[
        "Home" => "index.md",
        "API" => "api.md",
    ],
)

deploydocs(;
    repo="github.com/kernelmethod/ChaChaCiphers.jl",
    devbranch="main",
)
