defmodule BitwiseIp.Mask do
  @moduledoc """
  Functions for handling CIDR prefix lengths as bitmasks.

  These functions are used internally by `BitwiseIp.Block` to parse CIDR
  notation. For example, the IPv4 CIDR prefix length `/12` corresponds to an
  unsigned 32-bit integer of 12 ones followed by 20 zeroes:
  `0b11111111111100000000000000000000`. This mask is used in a bitwise `AND`
  with an integer-encoded IPv4 address to extract the first 12 bits.

  In IPv6, the same prefix is an unsigned 128-bit integer of 12 ones followed
  by 116 zeroes. Because Elixir's integers don't have a fixed width, we must
  distinguish between IPv4 and IPv6 in the function signatures, similar to the
  `:proto` tag in the `t:BitwiseIp.t/0` struct.

  Since there's a limited domain & range for these functions, they're all
  compiled directly into function clauses to perform static lookups. There is
  no work done at run time to convert strings, perform bitwise math, or
  anything other than the tacit function dispatch.
  """

  import Bitwise

  @doc """
  An error-raising variant of `parse/2`.

  Given the protocol (either `:v4` or `:v6`) and the string representation of a
  prefix length (without the leading slash), this function looks up the
  corresponding bitmask. If the string cannot be parsed, it raises an
  `ArgumentError`.

  ## Examples

  ```
  iex> BitwiseIp.Mask.parse!(:v4, "12")
  4293918720

  iex> BitwiseIp.Mask.parse!(:v6, "12")
  340199290171201906221318119490500689920

  iex> BitwiseIp.Mask.parse!(:v4, "128")
  ** (ArgumentError) Invalid IPv4 mask "128"

  iex> BitwiseIp.Mask.parse!(:v6, "not a mask")
  ** (ArgumentError) Invalid IPv6 mask "not a mask"
  ```
  """

  @spec parse!(:v4, String.t()) :: integer()
  @spec parse!(:v6, String.t()) :: integer()

  def parse!(protocol, prefix) do
    case parse(protocol, prefix) do
      {:ok, mask} -> mask
      {:error, message} -> raise ArgumentError, message
    end
  end

  @doc """
  Parses a string prefix length into a bitmask.

  Given the protocol (either `:v4` or `:v6`) and the string representation of a
  prefix length (without the leading slash), this function looks up the
  corresponding bitmask. This is done in an error-safe way by returning a
  tagged tuple. To raise an error, use `parse!/2` instead.

  ## Examples

  ```
  iex> BitwiseIp.Mask.parse(:v4, "12")
  {:ok, 4293918720}

  iex> BitwiseIp.Mask.parse(:v6, "12")
  {:ok, 340199290171201906221318119490500689920}

  iex> BitwiseIp.Mask.parse(:v4, "128")
  {:error, "Invalid IPv4 mask \\"128\\""}

  iex> BitwiseIp.Mask.parse(:v6, "not a mask")
  {:error, "Invalid IPv6 mask \\"not a mask\\""}
  ```
  """

  @spec parse(:v4, String.t()) :: {:ok, integer()} | {:error, String.t()}
  @spec parse(:v6, String.t()) :: {:ok, integer()} | {:error, String.t()}

  def parse(protocol, prefix)

  @doc """
  Encodes an integer prefix length as a bitmask.

  Given the protocol (either `:v4` or `:v6`) and the number of leading ones in
  the prefix, this function looks up the corresponding bitmask. The function is
  only defined on valid prefix lengths: between 0 and 32 for IPv4 and between 0
  and 128 for IPv6. To undo this conversion, use `decode/2`.

  ## Examples

  ```
  iex> BitwiseIp.Mask.encode(:v4, 12)
  4293918720

  iex> BitwiseIp.Mask.encode(:v6, 12)
  340199290171201906221318119490500689920

  iex> BitwiseIp.Mask.encode(:v4, 128)
  ** (FunctionClauseError) no function clause matching in BitwiseIp.Mask.encode/2

  iex> BitwiseIp.Mask.encode(:v6, -12)
  ** (FunctionClauseError) no function clause matching in BitwiseIp.Mask.encode/2
  ```
  """

  @spec encode(:v4, 0..32) :: integer()
  @spec encode(:v6, 0..128) :: integer()

  def encode(protocol, prefix)

  @doc """
  Decodes a bitmask into an integer prefix length.

  Given the protocol (either `:v4` or `:v6`) and a valid bitmask for that
  protocol, this function looks up the number of leading ones used by the
  bitmask. The function is only defined on valid IPv4 and IPv6 bitmasks. To
  undo this conversion, use `encode/2`.

  ## Examples

  ```
  iex> BitwiseIp.Mask.decode(:v4, 0b11111111111100000000000000000000)
  12

  iex> BitwiseIp.Mask.decode(:v6, 0b11111111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)
  12

  iex> BitwiseIp.Mask.decode(:v4, 0b11111111111100000000000000000001)
  ** (FunctionClauseError) no function clause matching in BitwiseIp.Mask.decode/2

  iex> BitwiseIp.Mask.decode(:v6, 0b0101)
  ** (FunctionClauseError) no function clause matching in BitwiseIp.Mask.decode/2
  ```
  """

  @spec decode(:v4, integer()) :: 0..32
  @spec decode(:v6, integer()) :: 0..128

  def decode(protocol, mask)

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

  def parse(:v4, prefix) do
    {:error, "Invalid IPv4 mask #{inspect(prefix)}"}
  end

  def parse(:v6, prefix) do
    {:error, "Invalid IPv6 mask #{inspect(prefix)}"}
  end
end
