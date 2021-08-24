defmodule Bench.MixProject do
  use Mix.Project

  def project do
    [
      app: :bench,
      version: "0.0.0",
      elixir: "~> 1.11",
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:benchee, "~> 1.0"},
      {:benchee_html, "~> 1.0"},
      {:ip, "~> 1.1"},
      {:inet_cidr, "~> 1.0"},
      {:cidr, "~> 1.0"},
      {:cider, "~> 0.3"},
      {:bitwise_ip, path: ".."}
    ]
  end
end
