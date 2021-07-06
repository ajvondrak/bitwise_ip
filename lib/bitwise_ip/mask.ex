defmodule BitwiseIp.Mask do
  use Bitwise

  @type v4() :: 0..0xFFFFFFFF
  @type v6() :: 0..0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

  @spec parse!(:v4, String.t()) :: v4()
  @spec parse!(:v6, String.t()) :: v6()

  def parse!(protocol, mask) do
    case parse(protocol, mask) do
      {:ok, mask} -> mask
      {:error, message} -> raise ArgumentError, message
    end
  end

  @v4 0xFFFFFFFF

  @spec encode(:v4, 0..32) :: v4()
  @spec decode(:v4, v4()) :: 0..32
  @spec parse(:v4, String.t()) :: {:ok, v4()} | {:error, String.t()}

  for decoded <- 0..32 do
    <<encoded::32>> = <<(~~~(@v4 >>> decoded))::32>>
    def encode(:v4, unquote(decoded)), do: unquote(encoded)
    def decode(:v4, unquote(encoded)), do: unquote(decoded)
    def parse(:v4, unquote(to_string(decoded))), do: {:ok, unquote(encoded)}
  end

  @v6 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

  @spec encode(:v6, 0..128) :: v6()
  @spec decode(:v6, v6()) :: 0..128
  @spec parse(:v6, String.t()) :: {:ok, v6()} | {:error, String.t()}

  for decoded <- 0..128 do
    <<encoded::128>> = <<(~~~(@v6 >>> decoded))::128>>
    def encode(:v6, unquote(decoded)), do: unquote(encoded)
    def decode(:v6, unquote(encoded)), do: unquote(decoded)
    def parse(:v6, unquote(to_string(decoded))), do: {:ok, unquote(encoded)}
  end

  def parse(:v4, mask) do
    {:error, "Invalid IPv4 mask #{inspect(mask)}"}
  end

  def parse(:v6, mask) do
    {:error, "Invalid IPv6 mask #{inspect(mask)}"}
  end
end
