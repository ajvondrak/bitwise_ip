defmodule BitwiseIp.Block do
  @moduledoc """
  A struct representing a range of bitwise IP addresses.

  Since 1993, [classless inter-domain routing (CIDR)][cidr] has been the basis
  for allocating blocks of IP addresses and efficiently routing between them.

  [cidr]: https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing

  If you think about the standard human-readable notation for IP addresses, a
  CIDR block is essentially a pattern with "wildcards" at the end. For example,
  `1.2.3.x` would contain the 256 different IPv4 addresses ranging from
  `1.2.3.0` through `1.2.3.255`. The CIDR representation would use the starting
  address `1.2.3.0` plus a bitmask where the first three bytes (the
  non-wildcards) are all ones. In IPv4 notation, the mask would be
  `255.255.255.0`. But rather than use wildcards, CIDR blocks have their own
  notation consisting of the starting address, a slash (`/`), and a prefix
  length - the number of leading ones in the mask. So the `1.2.3.x` block would
  actually be written as `1.2.3.0/24`.

  As the basis for modern IP routing, these blocks are commonly used as virtual
  collections. The CIDR representation allows us to efficiently test an
  incoming IP address for membership in the block by bitwise `AND`-ing the mask
  with the incoming address and comparing the result to the block's starting
  address. The size of the block can also be computed in constant time using
  bitwise arithmetic on the mask. For example, from the `/24` IPv4 mask we
  could infer there are 2^8 = 256 addresses in the range corresponding to the
  remaining 8 least significant bits.

  Using this foundation, `BitwiseIp.Block` is able to implement the
  `Enumerable` protocol with `BitwiseIp` structs as members. This allows you to
  manipulate blocks as generic collections without actually allocating an
  entire list:

  ```
  iex> :rand.seed(:exs1024, {0, 0, 0})
  iex> BitwiseIp.Block.parse!("1.2.3.0/24") |> Enum.random() |> to_string()
  "1.2.3.115"

  iex> BitwiseIp.Block.parse!("1.2.3.0/30") |> Enum.map(&to_string/1)
  ["1.2.3.0", "1.2.3.1", "1.2.3.2", "1.2.3.3"]
  ```

  Note that, while CIDR blocks are efficient on their own, they're locked into
  this very specific prefix representation. For example, you couldn't represent
  the range `1.2.3.10` through `1.2.3.20` with a single block, since the binary
  representation isn't amenable to a single prefix. This means you typically
  have to manipulate multiple blocks at a time. To ensure lists of blocks are
  handled efficiently, use the `BitwiseIp.Blocks` module.
  """

  defstruct [:proto, :addr, :mask]

  import Bitwise
  alias __MODULE__

  @typedoc """
  A bitwise IP address block.

  The block consists of all IP addresses that share the same prefix. To
  represent this, we use a struct with the following fields:

  * `:proto` - the protocol, either `:v4` or `:v6`
  * `:addr` - the integer encoding of the network prefix
  * `:mask` - the integer encoding of the subnet mask

  Logically, this type is a combination of `t:BitwiseIp.t/0` and an integer
  encoded by `BitwiseIp.Mask.encode/2`. However, rather than hold onto a
  literal `BitwiseIp` struct, the `:proto` and `:addr` fields are inlined. This
  proves to be more efficient for pattern matching than using a nested struct.

  The network prefix's least significant bits are all assumed to be zero,
  effectively making it the starting address of the block. That way, we can
  avoid performing repetitive bitwise `AND` operations between the prefix &
  mask in functions such as `member?/2`.
  """

  @type t() :: v4() | v6()

  @typedoc """
  An IPv4 block.

  The `:proto` and `:addr` are the same as in `t:BitwiseIp.v4/0`. The mask is a
  32-bit unsigned integer where some number of leading bits are one and the
  rest are zero. See `t:t/0` for more details.
  """

  @type v4() :: %Block{proto: :v4, addr: integer(), mask: integer()}

  @typedoc """
  An IPv6 block.

  The `:proto` and `:addr` are the same as in `t:BitwiseIp.v6/0`. The mask is a
  128-bit unsigned integer where some number of leading bits are one and the
  rest are zero. See `t:t/0` for more details.
  """

  @type v6() :: %Block{proto: :v6, addr: integer(), mask: integer()}

  @doc """
  Efficiently checks if a bitwise IP is within a block.

  In effect, we're testing if the given IP address has the same prefix as the
  block. This involves a single bitwise `AND` and an integer comparison. We
  extract the prefix from the IP by applying the block's bitmask, then check if
  it's equal to the block's starting address. If the block and the IP have
  different protocols, this function will return `false`.

  Because `BitwiseIp.Block` implements the `Enumerable` protocol, you may also
  use `in/2` to test for membership.

  ## Examples

  ```
  iex> BitwiseIp.Block.parse!("192.168.0.0/16")
  ...> |> BitwiseIp.Block.member?(BitwiseIp.parse!("192.168.10.1"))
  true

  iex> BitwiseIp.Block.parse!("192.168.0.0/16")
  ...> |> BitwiseIp.Block.member?(BitwiseIp.parse!("172.16.0.1"))
  false

  iex> BitwiseIp.parse!("d:e:a:d:b:e:e:f") in BitwiseIp.Block.parse!("d::/16")
  true

  iex> BitwiseIp.parse!("127.0.0.1") in BitwiseIp.Block.parse!("::/0")
  false
  ```
  """

  @spec member?(t(), BitwiseIp.t()) :: boolean()

  def member?(block, bitwise_ip)

  def member?(
        %Block{proto: proto, addr: prefix, mask: mask},
        %BitwiseIp{proto: proto, addr: ip}
      ) do
    prefix == band(ip, mask)
  end

  def member?(_, _) do
    false
  end

  @doc """
  Efficiently checks if `block2` is a subset of `block1`.

  Thanks to `BitwiseIp.Mask`, we encode masks as integers. So if mask A is less
  than mask B, that means A had fewer leading bits, meaning the block will
  contain *more* addresses than the block for B. Therefore, as a prerequisite,
  we first check that `block1`'s mask is `<=` `block2`'s mask. If not, then
  there's no chance that `block2` could be wholly contained in `block1`.

  Then, if `block1`'s range is wide enough, we can test an arbitrary IP from
  `block2` for membership in `block1`. Its inclusion would imply that
  everything else in `block2` is also included, since `block1` is wider. We
  have a suitable address to test in the form of the `:addr` field from
  `block2`. The membership check involves the same bitwise `AND` + integer
  comparison as `member?/2`.

  If the blocks don't have matching protocols, this function returns `false`.

  ## Examples

  ```
  iex> BitwiseIp.Block.parse!("1.0.0.0/8")
  ...> |> BitwiseIp.Block.subnet?(BitwiseIp.Block.parse!("1.2.0.0/16"))
  true

  iex> BitwiseIp.Block.parse!("1.2.0.0/16")
  ...> |> BitwiseIp.Block.subnet?(BitwiseIp.Block.parse!("1.0.0.0/8"))
  false

  iex> BitwiseIp.Block.parse!("1.2.0.0/16")
  ...> |> BitwiseIp.Block.subnet?(BitwiseIp.Block.parse!("1.2.0.0/16"))
  true

  iex> BitwiseIp.Block.parse!("1.2.0.0/16")
  ...> |> BitwiseIp.Block.subnet?(BitwiseIp.Block.parse!("2.3.0.0/16"))
  false
  ```
  """

  @spec subnet?(t(), t()) :: boolean()

  def subnet?(block1, block2)

  def subnet?(
        %Block{proto: proto, addr: prefix, mask: mask},
        %Block{proto: proto, addr: ip, mask: submask}
      )
      when mask <= submask do
    prefix == band(ip, mask)
  end

  def subnet?(_, _) do
    false
  end

  @doc """
  Computes the number of addresses contained in a block.

  This value is wholly determined by the `:mask` field. Taking the bitwise
  complement of the mask gives us an unsigned integer where all the lower bits
  are ones. Since these are the bits that are covered by the block, we can
  interpret this as the number of possible values, minus one for the zeroth
  address.

  For example, the IPv4 prefix `/29` leaves 3 bits to represent different
  addresses in the block. So that's 2^3 = 8 possible addresses. To get there
  from the mask `0b11111111111111111111111111111000`, we take its complement
  and get `0b00000000000000000000000000000111`, which represents the integer
  2^3 - 1 = 7. We add 1 and get the 8 possible addresses.

  Because of the limited number of possible masks, we might want to implement
  this as a static lookup using pattern matched function clauses, thereby
  avoiding binary manipulation altogether. However, benchmarks indicate that
  pattern matching against structs is much slower than the required bitwise
  math. So, we negate the mask and add 1 to the resulting integer at run time.

  ## Examples

  ```
  iex> BitwiseIp.Block.parse!("1.2.3.4/32") |> BitwiseIp.Block.size()
  1
  iex> BitwiseIp.Block.parse!("1.2.3.4/31") |> BitwiseIp.Block.size()
  2
  iex> BitwiseIp.Block.parse!("1.2.3.4/30") |> BitwiseIp.Block.size()
  4
  iex> BitwiseIp.Block.parse!("1.2.3.4/29") |> BitwiseIp.Block.size()
  8

  iex> BitwiseIp.Block.parse!("::/124") |> BitwiseIp.Block.size()
  16
  iex> BitwiseIp.Block.parse!("::/123") |> BitwiseIp.Block.size()
  32
  iex> BitwiseIp.Block.parse!("::/122") |> BitwiseIp.Block.size()
  64
  iex> BitwiseIp.Block.parse!("::/121") |> BitwiseIp.Block.size()
  128
  ```
  """

  @spec size(t()) :: integer()

  def size(%Block{proto: :v4, mask: mask}) do
    :binary.decode_unsigned(<<bnot(mask)::32>>) + 1
  end

  def size(%Block{proto: :v6, mask: mask}) do
    :binary.decode_unsigned(<<bnot(mask)::128>>) + 1
  end

  @doc """
  An error-raising variant of `parse/1`.

  This function parses strings in [CIDR
  notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation),
  where an IP address is followed by a prefix length composed of a slash (`/`)
  and a decimal number of leading bits in the subnet mask. The prefix length is
  optional. If missing, it defaults to the full width of the IP address: 32
  bits for IPv4, 128 for IPv6.

  The constituent parts are parsed using `BitwiseIp.parse/1` and
  `BitwiseIp.Mask.parse/2`. The address has the mask applied before
  constructing the `BitwiseIp.Block` struct, thereby discarding any lower bits.
  If the string is invalid, this function raises an `ArgumentError`.

  `BitwiseIp.Block` implements the `String.Chars` protocol, so parsing can be
  undone using `to_string/1`.

  ## Examples

  ```
  iex> BitwiseIp.Block.parse!("192.168.0.0/16")
  %BitwiseIp.Block{proto: :v4, addr: 3232235520, mask: 4294901760}

  iex> BitwiseIp.Block.parse!("fc00::/8")
  %BitwiseIp.Block{proto: :v6, addr: 334965454937798799971759379190646833152, mask: 338953138925153547590470800371487866880}

  iex> BitwiseIp.Block.parse!("256.0.0.0/8")
  ** (ArgumentError) Invalid IP address "256.0.0.0" in CIDR "256.0.0.0/8"

  iex> BitwiseIp.Block.parse!("dead::beef/129")
  ** (ArgumentError) Invalid IPv6 mask "129" in CIDR "dead::beef/129"

  iex> BitwiseIp.Block.parse!("192.168.0.0/8") |> to_string()
  "192.0.0.0/8"

  iex> BitwiseIp.Block.parse!("::") |> to_string()
  "::/128"
  ```
  """

  @spec parse!(String.t()) :: t()

  def parse!(cidr) do
    case parse(cidr) do
      {:ok, block} -> block
      {:error, message} -> raise ArgumentError, message
    end
  end

  @doc """
  Parses a bitwise IP block from a string in CIDR notation.

  This function parses strings in [CIDR
  notation](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation),
  where an IP address is followed by a prefix length composed of a slash (`/`)
  and a decimal number of leading bits in the subnet mask. The prefix length is
  optional. If missing, it defaults to the full width of the IP address: 32
  bits for IPv4, 128 for IPv6.

  The constituent parts are parsed using `BitwiseIp.parse/1` and
  `BitwiseIp.Mask.parse/2`. The address has the mask applied before
  constructing the `BitwiseIp.Block` struct, thereby discarding any lower bits.
  This parsing is done in an error-safe way by returning a tagged tuple. To
  raise an error, use `parse!/1` instead.

  `BitwiseIp.Block` implements the `String.Chars` protocol, so parsing can be
  undone using `to_string/1`.

  ## Examples

  ```
  iex> BitwiseIp.Block.parse("192.168.0.0/16")
  {:ok, %BitwiseIp.Block{proto: :v4, addr: 3232235520, mask: 4294901760}}

  iex> BitwiseIp.Block.parse("fc00::/8")
  {:ok, %BitwiseIp.Block{proto: :v6, addr: 334965454937798799971759379190646833152, mask: 338953138925153547590470800371487866880}}

  iex> BitwiseIp.Block.parse("256.0.0.0/8")
  {:error, "Invalid IP address \\"256.0.0.0\\" in CIDR \\"256.0.0.0/8\\""}

  iex> BitwiseIp.Block.parse("dead::beef/129")
  {:error, "Invalid IPv6 mask \\"129\\" in CIDR \\"dead::beef/129\\""}

  iex> BitwiseIp.Block.parse("192.168.0.0/8") |> elem(1) |> to_string()
  "192.0.0.0/8"

  iex> BitwiseIp.Block.parse("::") |> elem(1) |> to_string()
  "::/128"
  ```
  """

  @spec parse(String.t()) :: {:ok, t()} | {:error, String.t()}

  def parse(cidr) do
    case parse_with_or_without_mask(cidr) do
      {:error, e} -> {:error, "#{e} in CIDR #{inspect(cidr)}"}
      ok -> ok
    end
  end

  defp parse_with_or_without_mask(cidr) do
    case String.split(cidr, "/", parts: 2) do
      [ip] -> parse_without_mask(ip)
      [ip, mask] -> parse_with_mask(ip, mask)
    end
  end

  defp parse_with_mask(ip, mask) do
    with {:ok, ip} <- BitwiseIp.parse(ip),
         {:ok, mask} <- BitwiseIp.Mask.parse(ip.proto, mask) do
      {:ok, %Block{proto: ip.proto, addr: band(ip.addr, mask), mask: mask}}
    end
  end

  @v4 BitwiseIp.Mask.encode(:v4, 32)
  @v6 BitwiseIp.Mask.encode(:v6, 128)

  defp parse_without_mask(ip) do
    with {:ok, ip} <- BitwiseIp.parse(ip) do
      case ip.proto do
        :v4 -> {:ok, %Block{proto: :v4, addr: ip.addr, mask: @v4}}
        :v6 -> {:ok, %Block{proto: :v6, addr: ip.addr, mask: @v6}}
      end
    end
  end

  defimpl String.Chars do
    def to_string(block) do
      ip = %BitwiseIp{proto: block.proto, addr: block.addr}
      mask = BitwiseIp.Mask.decode(block.proto, block.mask)
      "#{ip}/#{mask}"
    end
  end

  defimpl Enumerable do
    def member?(block, ip) do
      {:ok, Block.member?(block, ip)}
    end

    def count(block) do
      {:ok, Block.size(block)}
    end

    def slice(%Block{proto: proto, addr: addr} = block) do
      size = Block.size(block)
      {:ok, size, &slice(proto, addr + &1, &2, &3)}
    end

    defp slice(proto, addr, 1, _step) do
      [%BitwiseIp{proto: proto, addr: addr}]
    end

    defp slice(proto, addr, n, s) do
      [%BitwiseIp{proto: proto, addr: addr} | slice(proto, addr + s, n - 1, s)]
    end

    def reduce(%Block{proto: proto, addr: addr} = block, acc, fun) do
      size = Block.size(block)
      reduce(proto, addr, addr + size - 1, acc, fun)
    end

    defp reduce(_proto, _addr, _last, {:halt, acc}, _fun) do
      {:halted, acc}
    end

    defp reduce(proto, addr, last, {:suspend, acc}, fun) do
      {:suspended, acc, &reduce(proto, addr, last, &1, fun)}
    end

    defp reduce(proto, addr, last, {:cont, acc}, fun) do
      if addr <= last do
        ip = %BitwiseIp{proto: proto, addr: addr}
        reduce(proto, addr + 1, last, fun.(ip, acc), fun)
      else
        {:done, acc}
      end
    end
  end
end
