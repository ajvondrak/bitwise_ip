defmodule BitwiseIp.MixProject do
  use Mix.Project

  def project do
    [
      app: :bitwise_ip,
      version: "0.1.0",
      elixir: "~> 1.11"
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end
end
