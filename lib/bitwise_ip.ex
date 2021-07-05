defmodule BitwiseIp do
  defstruct [:proto, :addr]

  def parse!(address) do
    case parse(address) do
      {:ok, ip} -> ip
      {:error, message} -> raise ArgumentError, message
    end
  end

  def parse(address) do
    case :inet.parse_strict_address(address |> to_charlist()) do
      {:ok, ip} -> {:ok, encode(ip)}
      {:error, _} -> {:error, "Invalid IP address #{inspect(address)}"}
    end
  end

  def encode({a, b, c, d}) do
    <<ip::32>> = <<a::8, b::8, c::8, d::8>>
    %BitwiseIp{proto: :v4, addr: ip}
  end

  def encode({a, b, c, d, e, f, g, h}) do
    <<ip::128>> = <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    %BitwiseIp{proto: :v6, addr: ip}
  end

  def decode(%BitwiseIp{proto: :v4, addr: ip}) do
    <<a::8, b::8, c::8, d::8>> = <<ip::32>>
    {a, b, c, d}
  end

  def decode(%BitwiseIp{proto: :v6, addr: ip}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = <<ip::128>>
    {a, b, c, d, e, f, g, h}
  end

  defimpl String.Chars do
    def to_string(ip) do
      BitwiseIp.decode(ip) |> :inet.ntoa() |> Kernel.to_string()
    end
  end
end
