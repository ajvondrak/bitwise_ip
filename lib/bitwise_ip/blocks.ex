defmodule BitwiseIp.Blocks do
  @moduledoc """
  Functions for handling lists of bitwise IP blocks.

  Because the `BitwiseIp.Block` representation relies on a binary prefix, it's
  not possible to express certain ranges with a single block. For instance, the
  range of addresses between `192.168.12.0` and `192.168.16.255` might make
  intuitive sense, but the binary representation of the third byte presents a
  challenge:

  * `12` = `0b00001100`
  * `13` = `0b00001101`
  * `14` = `0b00001110`
  * `15` = `0b00001111`
  * `16` = `0b00010000`

  Notice that `12`-`15` share the prefix `0b000011xx`, so those addresses could
  be covered by the CIDR block `192.168.12.0/22`. (The prefix length is 22 for
  the 16 bits of `192.168.` plus the 6 most significant bits of the third
  byte.) But that would *not* cover the `192.168.16.x` addresses:

  ```
  iex> BitwiseIp.Block.parse!("192.168.12.0/22")
  ...> |> Enum.take_every(256)
  ...> |> Enum.map(&to_string/1)
  ["192.168.12.0", "192.168.13.0", "192.168.14.0", "192.168.15.0"]
  ```

  All this is to say that there are general limitations to the expressiveness
  of a single CIDR range, so it's natural that most applications will deal with
  a collection of blocks at a time - conceptually, a list of lists of IP
  addresses.

  Whereas bitwise IP blocks have a straightforward binary representation, a
  list of blocks is somewhat more unwieldy. This module provides utility
  functions that make handling these lists more ergonomic. In particular, the
  `member?/2` function helps you avoid a common performance pitfall.
  """

  @typedoc """
  A list of bitwise IP blocks.

  The `BitwiseIp.Blocks` module operates over lists of `BitwiseIp.Block`
  structs. This itself does not warrant a separate struct with any extra
  indirection, so we just use lists directly.
  """

  @type t() :: [BitwiseIp.Block.t()]

  @doc """
  Efficiently checks if an IP address is a member of any of the blocks.

  Libraries will generally handle IP addresses encoded as `:inet`-style tuples
  of integers. Therefore, in order to use `BitwiseIp.Block.member?/2`, you'll
  first need to use `BitwiseIp.encode/1` to convert the tuple into an
  integer-encoded struct.

  A common mistake when handling a list of blocks is to do the bitwise IP
  encoding repeatedly within a loop:

  ```
  # This is a mistake!
  ip = {127, 0, 0, 1}
  Enum.any?(blocks, &BitwiseIp.Block.member?(&1, BitwiseIp.encode(ip)))
  ```

  The problem with the above is that the return value of `BitwiseIp.encode(ip)`
  doesn't change as we iterate through the list. The cost of redundantly
  encoding the same IP address over & over is often enough to outweigh any
  performance gains from using the bitwise membership checks.

  This function helps enforce a pattern where the encoding is only done once
  (essentially performing [loop-invariant code
  motion](https://en.wikipedia.org/wiki/Loop-invariant_code_motion)). That is,
  it's akin to saying:

  ```
  ip = {127, 0, 0, 1}
  encoded = BitwiseIp.encode(ip) # this is only done once
  Enum.any?(blocks, &BitwiseIp.Block.member?(&1, encoded))
  ```

  This function also accepts an already-encoded `BitwiseIp` struct as an
  argument, in which case no extra encoding needs to be performed. This is
  useful for cases where you need to perform even more loop-invariant code
  motion, such as when you're handling two separate lists. In such a case, you
  should use a pattern like:

  ```
  # make sure to only encode the IP once
  ip = {127, 0, 0, 1}
  encoded = BitwiseIp.encode(ip)

  BitwiseIp.Blocks.member?(blocks1, encoded) # check the first list
  BitwiseIp.Blocks.member?(blocks2, encoded) # check the second list
  ```

  ## Examples

  ```
  iex> ["1.2.0.0/16", "3.4.0.0/16", "5.6.0.0/16"]
  ...> |> Enum.map(&BitwiseIp.Block.parse!/1)
  ...> |> BitwiseIp.Blocks.member?({1, 2, 3, 4})
  true

  iex> ["1.2.0.0/16", "3.4.0.0/16", "5.6.0.0/16"]
  ...> |> Enum.map(&BitwiseIp.Block.parse!/1)
  ...> |> BitwiseIp.Blocks.member?({7, 8, 9, 10})
  false

  iex> ["1.2.0.0/16", "3.4.0.0/16", "5.6.0.0/16"]
  ...> |> Enum.map(&BitwiseIp.Block.parse!/1)
  ...> |> BitwiseIp.Blocks.member?(BitwiseIp.encode({1, 2, 3, 4}))
  true

  iex> ["1.2.0.0/16", "3.4.0.0/16", "5.6.0.0/16"]
  ...> |> Enum.map(&BitwiseIp.Block.parse!/1)
  ...> |> BitwiseIp.Blocks.member?(BitwiseIp.encode({7, 8, 9, 10}))
  false
  ```
  """

  @spec member?(t(), BitwiseIp.t()) :: boolean()

  def member?(blocks, %BitwiseIp{} = ip) do
    Enum.any?(blocks, &BitwiseIp.Block.member?(&1, ip))
  end

  @spec member?(t(), :inet.ip_address()) :: boolean()

  def member?(blocks, ip) do
    member?(blocks, BitwiseIp.encode(ip))
  end

  @doc """
  An error-raising variant of `parse/1`.

  This function takes a list of strings in CIDR notation and parses them into
  bitwise IP blocks using `BitwiseIp.Block.parse!/1`. If any of the strings are
  invalid, the whole list fails to parse and the error is propagated. If you
  want to discard invalid elements instead, use `parse/1`.

  ## Examples

  ```
  iex> BitwiseIp.Blocks.parse!(["3.14.0.0/16", "dead::beef"])
  ...> |> Enum.map(&to_string/1)
  ["3.14.0.0/16", "dead::beef/128"]

  iex> BitwiseIp.Blocks.parse!(["3.14/16", "invalid", "dead::cow"])
  ** (ArgumentError) Invalid IP address "3.14" in CIDR "3.14/16"

  iex> BitwiseIp.Blocks.parse!(["3.14.0.0/16", "invalid", "dead::beef"])
  ** (ArgumentError) Invalid IP address "invalid" in CIDR "invalid"
  ```
  """

  @spec parse!([String.t()]) :: t()

  def parse!(cidrs) do
    Enum.map(cidrs, &BitwiseIp.Block.parse!/1)
  end

  @doc """
  Parses a list of strings into bitwise IP blocks.

  This function takes a list of strings in CIDR notation and parses them into
  bitwise IP blocks using `BitwiseIp.Block.parse/1`. If a string is invalid,
  its value is discarded from the resulting list. If you want to raise an error
  instead, use `parse!/1`.

  ## Examples

  ```
  iex> BitwiseIp.Blocks.parse(["3.14.0.0/16", "dead::beef"])
  ...> |> Enum.map(&to_string/1)
  ["3.14.0.0/16", "dead::beef/128"]

  iex> BitwiseIp.Blocks.parse(["3.14/16", "invalid", "dead::cow"])
  []

  iex> BitwiseIp.Blocks.parse(["3.14.0.0/16", "invalid", "dead::beef"])
  ...> |> Enum.map(&to_string/1)
  ["3.14.0.0/16", "dead::beef/128"]
  ```
  """

  @spec parse([String.t()]) :: t()

  def parse(cidrs)

  def parse([cidr | cidrs]) do
    case BitwiseIp.Block.parse(cidr) do
      {:ok, block} -> [block | parse(cidrs)]
      {:error, _} -> parse(cidrs)
    end
  end

  def parse([]) do
    []
  end

  @doc """
  Computes an equivalent list of blocks optimal for `member?/2`.

  While an individual `BitwiseIp.Block.member?/2` call is already efficient,
  the performance of `member?/2` is sensitive to a couple of factors:

  1. The size of the list matters, since a smaller list requires fewer
     individual checks.

  2. The order of the elements in the list matters, since `member?/2` will exit
     early as soon as any individual check returns true.

  To optimize for the size of the list, this function recursively merges any
  two blocks where one is a subset of the other. This is tested using
  `BitwiseIp.Block.subnet?/2`. For example, `1.2.0.0/16` is a subset of
  `1.0.0.0/8`, so instead of calling `BitwiseIp.Block.member?/2` on both of
  them, we can simply check the larger range of the two - in this case,
  `1.0.0.0/8`.

  The order can be optimized by placing larger blocks earlier in the list.
  Assuming an even distribution of IP addresses, it's more likely for an
  address to fall inside of a block that covers a wider range. Thus, we can
  sort by the integer-encoded mask: a smaller mask means a shorter network
  prefix, which means there are more addresses possible (see
  `BitwiseIp.Block.size/1` for more on computing the size of a block from its
  mask).

  This optimization is kind of a parlor trick cribbed from the
  [cider](https://hex.pm/packages/cider) library. Except in pathological cases,
  the run time cost of performing the optimization is likely larger than any
  performance gained by using the new list. As such, if you're going to use
  this function at all, it's only really appropriate to call at compile time,
  which means your original list of blocks has to be available statically.

  ## Examples

  ```
  iex> ["1.2.3.4", "1.2.3.0/24", "1.2.0.0/16", "1.0.0.0/8"]
  ...> |> BitwiseIp.Blocks.parse!()
  ...> |> BitwiseIp.Blocks.optimize()
  ...> |> Enum.map(&to_string/1)
  ["1.0.0.0/8"]

  iex> ["1.2.0.0/16", "3.0.0.0/8"]
  ...> |> BitwiseIp.Blocks.parse!()
  ...> |> BitwiseIp.Blocks.optimize()
  ...> |> Enum.map(&to_string/1)
  ["3.0.0.0/8", "1.2.0.0/16"]

  iex> ["1.2.0.0/16", "3.4.5.0/24", "1.0.0.0/8", "3.4.0.0/16"]
  ...> |> BitwiseIp.Blocks.parse!()
  ...> |> BitwiseIp.Blocks.optimize()
  ...> |> Enum.map(&to_string/1)
  ["1.0.0.0/8", "3.4.0.0/16"]
  ```
  """

  @spec optimize(t()) :: t()

  def optimize(blocks) do
    case try_to_optimize(blocks) do
      {:success, blocks} -> optimize(blocks)
      :failure -> blocks |> Enum.sort_by(& &1.mask)
    end
  end

  defp try_to_optimize(blocks, unmergeable \\ [])

  defp try_to_optimize([block | blocks], unmergeable) do
    case try_to_merge(block, blocks) do
      {:success, merged} -> {:success, merged ++ unmergeable}
      :failure -> try_to_optimize(blocks, [block | unmergeable])
    end
  end

  defp try_to_optimize([], _) do
    :failure
  end

  defp try_to_merge(block, blocks, visited \\ [])

  defp try_to_merge(a, [b | unvisited], visited) do
    cond do
      BitwiseIp.Block.subnet?(a, b) -> {:success, [a | unvisited] ++ visited}
      BitwiseIp.Block.subnet?(b, a) -> {:success, [b | unvisited] ++ visited}
      true -> try_to_merge(a, unvisited, [b | visited])
    end
  end

  defp try_to_merge(_, [], _) do
    :failure
  end
end
