defmodule BitwiseIp.Mask do
  use Bitwise

  def parse!(protocol, mask) do
    case parse(protocol, mask) do
      {:ok, mask} -> mask
      {:error, message} -> raise ArgumentError, message
    end
  end

  @v4 0xFFFFFFFF

  for decoded <- 0..32 do
    <<encoded::32>> = <<(~~~(@v4 >>> decoded))::32>>
    def encode(:v4, unquote(decoded)), do: unquote(encoded)
    def decode(:v4, unquote(encoded)), do: unquote(decoded)
    def parse(:v4, unquote(to_string(decoded))), do: {:ok, unquote(encoded)}
  end

  @v6 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

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
