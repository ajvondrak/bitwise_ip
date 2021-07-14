defmodule BitwiseIp do
  @moduledoc """
  A struct representing an IP address encoded as an integer.

  The [Internet Protocol](https://en.wikipedia.org/wiki/Internet_Protocol)
  defines computer network addresses using fixed-width integers, which are
  efficient for both transmission and the implementation of logic using bitwise
  operations. [IPv4](https://en.wikipedia.org/wiki/IPv4) uses 32-bit integers,
  providing a space of 4,294,967,296 unique addresses. Due to the growing size
  of the internet, [IPv6](https://en.wikipedia.org/wiki/IPv6) uses 128-bit
  integers to provide an absurdly large address space.

  These integers, however, are hard for humans to read. Therefore, we've
  adopted customary notations that are a little easier to digest. IPv4 uses a
  dotted octet notation, where each of the four bytes are written in decimal
  notation and separated by `.`, as in `127.0.0.1`. IPv6 is similar, but uses
  hexadecimal notation on each of eight hextets separated by `:`, as in
  `a:1:b:2:c:3:d:4`.

  As such, representations for IP addresses in modern software have drifted
  away from fixed-width integers. `:inet` represents IP addresses as tuples
  like `{127, 0, 0, 1}` for IPv4 and `{0xA, 1, 0xB, 2, 0xC, 3, 0xD, 4}` for
  IPv6. These are less efficient in both the space to store the addresses and
  the time it takes to perform various operations. For example, whereas
  comparing two 32-bit IPv4 addresses is typically one machine instruction,
  comparing two tuples involves memory indirection for the tuple layout and 4
  separate integer comparisons. This could be even worse if you represent IPs
  as strings in their human-readable format.

  The difference is probably negligible for your application. In fact, Elixir &
  Erlang don't have great support for fixed-width integer representations (see
  `t:t/0` for details). But in the interest of getting back to basics,
  `BitwiseIp` provides the missing interface for manipulating IP addresses as
  the integers they were designed to be. This makes certain logic much easier
  to express and improves micro-benchmarks compared to tuple-based libraries
  (for whatever that's worth). The most useful functionality is in
  `BitwiseIp.Block`, which represents a
  [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) block.
  However, `BitwiseIp` is the fundamental structure that `BitwiseIp.Block` is
  built on.
  """

  defstruct [:proto, :addr]

  @typedoc """
  An integer-encoded IP address.

  This type takes on two different shapes depending on the IP protocol. The
  supported protocols are IPv4 and IPv6.

  Normally, the distinction would be down to the number of bits in a
  fixed-width integer representation. However, the Erlang VM doesn't support
  fixed-width integers, so there's no way to tell IPv4 addresses apart from
  IPv6 addresses using just a number. Therefore, this type is a struct with two
  fields:

  * `:proto` - the protocol, either `:v4` or `:v6`
  * `:addr` - the integer encoding of the address

  But again, the VM does not support fixed-width integers for the `:addr`. In
  the Erlang runtime system, the smallest unit of memory is a *word*: 4 bytes
  on a 32-bit architecture, 8 bytes on a 64-bit architecture. Data is stored
  using *tagged pointers*, where one word has 4 bits reserved as a *tag*
  enumerating type information. One pattern of 4 bits says "I'm a float",
  another pattern says "I'm an integer", and so on. When the data is small
  enough to fit in the remaining bits of the word (28 bits or 60 bits,
  depending on the architecture), it is stored as an *immediate* value.
  Otherwise, it is *boxed* and the word instead contains a pointer to a section
  of memory on the heap, which can basically be arbitrarily large. Read more in
  [*A staged tag scheme for
  Erlang*](http://www.it.uu.se/research/publications/reports/2000-029/) by
  Mikael Pettersson.

  What this means for us is that `:addr` may or may not spill onto the heap. On
  a 32-bit machine, only IP addresses in the range of 0 to 2^28 fit as
  immediate values. This covers most of the IPv4 range, but only a small
  portion of the IPv6 range. 64-bit machines have 60 bits to play with, which
  would comfortably fit any IPv4 address, but still requires boxing of IPv6
  addresses. According to the [Erlang efficiency
  guide](http://erlang.org/doc/efficiency_guide/advanced.html), large integers
  are stored across at least 3 words. What's more, because we have to
  distinguish between integers using the struct with the `:proto` field, each
  IP address requires an additional map allocation, which carries some
  overhead.

  So this isn't going to be a maximally compact representation of an IP
  address. Such a thing isn't really possible on the Erlang VM. However,
  storing the bulk of it as a single integer still lets us perform efficient
  bitwise operations with less overhead than, say, `:inet`-style tuples of
  multiple integers.
  """

  @type t() :: v4() | v6()

  @typedoc """
  An IPv4 address.

  The `:addr` is an unsigned integer between 0 and 2^32 - 1. See `t:t/0` for
  discussion about the in-memory representation.
  """

  @type v4() :: %BitwiseIp{proto: :v4, addr: integer()}

  @typedoc """
  An IPv6 address.

  The `:addr` is an unsigned integer between 0 and 2^128 - 1. See `t:t/0` for
  discussion about the in-memory representation.
  """

  @type v6() :: %BitwiseIp{proto: :v6, addr: integer()}

  @doc """
  An error-raising variant of `parse/1`.

  This function parses IPv4 and IPv6 strings in their respective notations and
  produces an encoded `BitwiseIp` struct. If the string is invalid, it raises
  an `ArgumentError`.

  `BitwiseIp` implements the `String.Chars` protocol, so parsing can be undone
  using `to_string/1`.

  ## Examples

  ```
  iex> BitwiseIp.parse!("127.0.0.1")
  %BitwiseIp{proto: :v4, addr: 2130706433}

  iex> BitwiseIp.parse!("::1")
  %BitwiseIp{proto: :v6, addr: 1}

  iex> BitwiseIp.parse!("not an ip")
  ** (ArgumentError) Invalid IP address "not an ip"

  iex> BitwiseIp.parse!("192.168.0.1") |> to_string()
  "192.168.0.1"

  iex> BitwiseIp.parse!("fc00::") |> to_string()
  "fc00::"
  ```
  """

  @spec parse!(String.t()) :: t()

  def parse!(address) do
    case parse(address) do
      {:ok, ip} -> ip
      {:error, message} -> raise ArgumentError, message
    end
  end

  @doc """
  Parses a string into a bitwise IP.

  This function parses IPv4 and IPv6 strings in their respective notations and
  produces an encoded `BitwiseIp` struct. This is done in an error-safe way by
  returning a tagged tuple. To raise an error, use `parse!/1` instead.

  `BitwiseIp` implements the `String.Chars` protocol, so parsing can be undone
  using `to_string/1`.

  ## Examples

  ```
  iex> BitwiseIp.parse("127.0.0.1")
  {:ok, %BitwiseIp{proto: :v4, addr: 2130706433}}

  iex> BitwiseIp.parse("::1")
  {:ok, %BitwiseIp{proto: :v6, addr: 1}}

  iex> BitwiseIp.parse("not an ip")
  {:error, "Invalid IP address \\"not an ip\\""}

  iex> BitwiseIp.parse("192.168.0.1") |> elem(1) |> to_string()
  "192.168.0.1"

  iex> BitwiseIp.parse("fc00::") |> elem(1) |> to_string()
  "fc00::"
  ```
  """

  @spec parse(String.t()) :: {:ok, t()} | {:error, String.t()}

  def parse(address) do
    case :inet.parse_strict_address(address |> to_charlist()) do
      {:ok, ip} -> {:ok, encode(ip)}
      {:error, _} -> {:error, "Invalid IP address #{inspect(address)}"}
    end
  end

  @doc """
  Encodes an `:inet`-style tuple as a bitwise IP.

  The Erlang standard library represents IP addresses as tuples of integers: 4
  octet values for IPv4, 8 hextet values for IPv6. This function encodes the
  separate values as a single number, which gets wrapped into a `BitwiseIp`
  struct. This can be undone with `decode/1`.

  Beware of redundant usage in performance-critical paths. Because of the
  overhead in encoding the integer, excessive translation back & forth between
  the formats may outweigh any benefits gained from other operations on the
  single-integer representation.

  ## Examples

  ```
  iex> BitwiseIp.encode({127, 0, 0, 1})
  %BitwiseIp{proto: :v4, addr: 2130706433}

  iex> BitwiseIp.encode({0, 0, 0, 0, 0, 0, 0, 1})
  %BitwiseIp{proto: :v6, addr: 1}
  ```
  """

  def encode(inet)

  @spec encode(:inet.ip4_address()) :: v4()

  def encode({a, b, c, d}) do
    <<ip::32>> = <<a::8, b::8, c::8, d::8>>
    %BitwiseIp{proto: :v4, addr: ip}
  end

  @spec encode(:inet.ip6_address()) :: v6()

  def encode({a, b, c, d, e, f, g, h}) do
    <<ip::128>> = <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
    %BitwiseIp{proto: :v6, addr: ip}
  end

  @doc """
  Decodes a bitwise IP into an `:inet`-style tuple.

  The Erlang standard library represents IP addresses as tuples of integers: 4
  octet values for IPv4, 8 hextet values for IPv6. This function decodes the
  single number from a `BitwiseIp` struct into its constituent parts. This can
  be undone with `encode/1`.

  Beware of redundant usage in performance-critical paths. Because of the
  overhead in decoding the integer, excessive translation back & forth between
  the formats may outweigh any benefits gained from other operations on the
  single-integer representation.

  ## Examples

  ```
  iex> BitwiseIp.decode(%BitwiseIp{proto: :v4, addr: 2130706433})
  {127, 0, 0, 1}

  iex> BitwiseIp.decode(%BitwiseIp{proto: :v6, addr: 1})
  {0, 0, 0, 0, 0, 0, 0, 1}
  ```
  """

  def decode(bitwise_ip)

  @spec decode(v4()) :: :inet.ip4_address()

  def decode(%BitwiseIp{proto: :v4, addr: ip}) do
    <<a::8, b::8, c::8, d::8>> = <<ip::32>>
    {a, b, c, d}
  end

  @spec decode(v6()) :: :inet.ip6_address()

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
