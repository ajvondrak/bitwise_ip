defmodule BitwiseIp.MixProject do
  use Mix.Project

  def project do
    [
      app: :bitwise_ip,
      version: "0.1.0",
      elixir: "~> 1.7",
      description: "Efficient IP address operations using bitwise arithmetic",
      package: %{
        files: ~w[lib mix.exs README.md LICENSE],
        licenses: ["MIT"],
        links: %{"GitHub" => "https://github.com/ajvondrak/bitwise_ip"}
      },
      deps: [
        {:ex_doc, "~> 0.24", only: [:dev], runtime: false},
        {:dialyxir, "~> 1.1", only: [:dev], runtime: false},
        {:excoveralls, "~> 0.14", only: [:test], runtime: false}
      ],
      docs: [source_url: "https://github.com/ajvondrak/bitwise_ip"],
      dialyzer: [plt_file: {:no_warn, "priv/plts/dialyzer.plt"}],
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ]
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end
end
