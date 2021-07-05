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
        {:excoveralls, "~> 0.14", only: [:test], runtime: false}
      ],
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
