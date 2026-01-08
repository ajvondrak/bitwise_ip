defmodule BitwiseIp.BlockTest do
  use ExUnit.Case, async: true
  doctest BitwiseIp.Block

  alias BitwiseIp.Mask
  alias BitwiseIp.Block

  def ipv4 do
    Stream.repeatedly(fn -> Enum.random(0..255) end)
    |> Enum.take(4)
    |> List.to_tuple()
  end

  def ipv6 do
    Stream.repeatedly(fn -> Enum.random(0..65_535) end)
    |> Enum.take(8)
    |> List.to_tuple()
  end

  def as_string({a, b, c, d}) do
    "#{a}.#{b}.#{c}.#{d}"
  end

  def as_string({_, _, _, _, _, _, _, _} = ip) do
    Tuple.to_list(ip)
    |> Enum.map(&Integer.to_string(&1, 16))
    |> Enum.join(":")
  end

  describe "parsing" do
    test "with or without exceptions" do
      {:ok, success} = Block.parse("127.0.0.1")
      assert Block.parse!("127.0.0.1") == success

      {:error, error} = Block.parse("127001")
      assert_raise ArgumentError, error, fn -> Block.parse!("127001") end
    end

    test "invalid CIDR" do
      assert_raise ArgumentError, ~S'Invalid IP address "invalid" in CIDR "invalid"', fn ->
        Block.parse!("invalid")
      end
    end

    test "invalid IPv4 address" do
      assert_raise ArgumentError, ~S'Invalid IP address "256.0.0.0" in CIDR "256.0.0.0/8"', fn ->
        Block.parse!("256.0.0.0/8")
      end
    end

    test "invalid IPv6 address" do
      assert_raise ArgumentError, ~S'Invalid IP address "f7::u" in CIDR "f7::u/12"', fn ->
        Block.parse!("f7::u/12")
      end
    end

    test "invalid IPv4 mask" do
      assert_raise ArgumentError, ~S'Invalid IPv4 mask "-1" in CIDR "1.2.3.4/-1"', fn ->
        Block.parse!("1.2.3.4/-1")
      end

      assert_raise ArgumentError, ~S'Invalid IPv4 mask "blah" in CIDR "1.2.3.4/blah"', fn ->
        Block.parse!("1.2.3.4/blah")
      end

      assert_raise ArgumentError, ~S'Invalid IPv4 mask "33" in CIDR "1.2.3.4/33"', fn ->
        Block.parse!("1.2.3.4/33")
      end
    end

    test "invalid IPv6 mask" do
      assert_raise ArgumentError, ~S'Invalid IPv6 mask "-1" in CIDR "::/-1"', fn ->
        Block.parse!("::/-1")
      end

      assert_raise ArgumentError, ~S'Invalid IPv6 mask "blah" in CIDR "::/blah"', fn ->
        Block.parse!("::/blah")
      end

      assert_raise ArgumentError, ~S'Invalid IPv6 mask "129" in CIDR "::/129"', fn ->
        Block.parse!("::/129")
      end
    end

    test "IPv4 address without mask" do
      ip = ipv4() |> as_string()
      assert Block.parse!(ip) == Block.parse!("#{ip}/32")
    end

    test "IPv6 address without mask" do
      ip = ipv6() |> as_string()
      assert Block.parse!(ip) == Block.parse!("#{ip}/128")
    end

    test "IPv4 address with mask" do
      octets = {a, b, c, d} = ipv4()
      ip = as_string(octets)

      addr_z = BitwiseIp.encode({0, 0, 0, 0}).addr
      addr_a = BitwiseIp.encode({a, 0, 0, 0}).addr
      addr_b = BitwiseIp.encode({a, b, 0, 0}).addr
      addr_c = BitwiseIp.encode({a, b, c, 0}).addr
      addr_d = BitwiseIp.encode({a, b, c, d}).addr
      addr_x = BitwiseIp.encode({a, :erlang.band(b, 0b11110000), 0, 0}).addr

      mask_z = Mask.encode(:v4, 0)
      mask_a = Mask.encode(:v4, 8)
      mask_b = Mask.encode(:v4, 16)
      mask_c = Mask.encode(:v4, 24)
      mask_d = Mask.encode(:v4, 32)
      mask_x = Mask.encode(:v4, 12)

      assert %Block{proto: :v4, addr: addr_z, mask: mask_z} == Block.parse!("#{ip}/0")
      assert %Block{proto: :v4, addr: addr_a, mask: mask_a} == Block.parse!("#{ip}/8")
      assert %Block{proto: :v4, addr: addr_b, mask: mask_b} == Block.parse!("#{ip}/16")
      assert %Block{proto: :v4, addr: addr_c, mask: mask_c} == Block.parse!("#{ip}/24")
      assert %Block{proto: :v4, addr: addr_d, mask: mask_d} == Block.parse!("#{ip}/32")
      assert %Block{proto: :v4, addr: addr_x, mask: mask_x} == Block.parse!("#{ip}/12")
    end

    test "IPv6 address with mask" do
      hextets = {a, b, c, d, e, f, g, h} = ipv6()
      ip = as_string(hextets)

      addr_z = BitwiseIp.encode({0, 0, 0, 0, 0, 0, 0, 0}).addr
      addr_a = BitwiseIp.encode({a, 0, 0, 0, 0, 0, 0, 0}).addr
      addr_b = BitwiseIp.encode({a, b, 0, 0, 0, 0, 0, 0}).addr
      addr_c = BitwiseIp.encode({a, b, c, 0, 0, 0, 0, 0}).addr
      addr_d = BitwiseIp.encode({a, b, c, d, 0, 0, 0, 0}).addr
      addr_e = BitwiseIp.encode({a, b, c, d, e, 0, 0, 0}).addr
      addr_f = BitwiseIp.encode({a, b, c, d, e, f, 0, 0}).addr
      addr_g = BitwiseIp.encode({a, b, c, d, e, f, g, 0}).addr
      addr_h = BitwiseIp.encode({a, b, c, d, e, f, g, h}).addr
      addr_x = BitwiseIp.encode({a, b, c, d, :erlang.band(e, 0b1000000000000000), 0, 0, 0}).addr

      mask_z = Mask.encode(:v6, 0)
      mask_a = Mask.encode(:v6, 16)
      mask_b = Mask.encode(:v6, 32)
      mask_c = Mask.encode(:v6, 48)
      mask_d = Mask.encode(:v6, 64)
      mask_e = Mask.encode(:v6, 80)
      mask_f = Mask.encode(:v6, 96)
      mask_g = Mask.encode(:v6, 112)
      mask_h = Mask.encode(:v6, 128)
      mask_x = Mask.encode(:v6, 65)

      assert %Block{proto: :v6, addr: addr_z, mask: mask_z} == Block.parse!("#{ip}/0")
      assert %Block{proto: :v6, addr: addr_a, mask: mask_a} == Block.parse!("#{ip}/16")
      assert %Block{proto: :v6, addr: addr_b, mask: mask_b} == Block.parse!("#{ip}/32")
      assert %Block{proto: :v6, addr: addr_c, mask: mask_c} == Block.parse!("#{ip}/48")
      assert %Block{proto: :v6, addr: addr_d, mask: mask_d} == Block.parse!("#{ip}/64")
      assert %Block{proto: :v6, addr: addr_e, mask: mask_e} == Block.parse!("#{ip}/80")
      assert %Block{proto: :v6, addr: addr_f, mask: mask_f} == Block.parse!("#{ip}/96")
      assert %Block{proto: :v6, addr: addr_g, mask: mask_g} == Block.parse!("#{ip}/112")
      assert %Block{proto: :v6, addr: addr_h, mask: mask_h} == Block.parse!("#{ip}/128")
      assert %Block{proto: :v6, addr: addr_x, mask: mask_x} == Block.parse!("#{ip}/65")
    end
  end

  describe "to_string/1" do
    test "IPv4" do
      assert "3.14.15.92/32" == Block.parse!("3.14.15.92/32") |> to_string()
      assert "3.14.15.0/24" == Block.parse!("3.14.15.92/24") |> to_string()
      assert "3.14.0.0/16" == Block.parse!("3.14.15.92/16") |> to_string()
      assert "3.0.0.0/8" == Block.parse!("3.14.15.92/8") |> to_string()
      assert "0.0.0.0/0" == Block.parse!("3.14.15.92/0") |> to_string()
    end

    test "IPv6" do
      assert "123::456/128" == Block.parse!("123::456/128") |> to_string()
      assert "123::/64" == Block.parse!("123::456/64") |> to_string()
      assert "::/0" == Block.parse!("123::456/0") |> to_string()
    end
  end

  describe "IPv4 membership" do
    test "inside block" do
      block = Block.parse!("192.168.0.0/16")

      for c <- 0..255, d <- 0..255 do
        assert Block.member?(block, BitwiseIp.encode({192, 168, c, d}))
      end
    end

    test "outside block" do
      block = Block.parse!("192.168.0.0/16")
      refute Block.member?(block, BitwiseIp.encode({192, 167, 255, 255}))
      refute Block.member?(block, BitwiseIp.encode({192, 169, 0, 0}))
      refute Block.member?(block, BitwiseIp.encode({191, 168, 0, 0}))
      refute Block.member?(block, BitwiseIp.encode({191, 255, 255, 255}))
      refute Block.member?(block, BitwiseIp.encode({194, 0, 0, 0}))
      refute Block.member?(block, BitwiseIp.encode({31, 41, 59, 27}))
    end

    test "with full-length prefix" do
      block = Block.parse!("127.0.0.1/32")
      refute Block.member?(block, BitwiseIp.encode({127, 0, 0, 0}))
      assert Block.member?(block, BitwiseIp.encode({127, 0, 0, 1}))
      refute Block.member?(block, BitwiseIp.encode({127, 0, 0, 2}))
    end

    test "with zero-length prefix" do
      block = Block.parse!("0.0.0.0/0")
      assert Block.member?(block, BitwiseIp.encode(ipv4()))
    end

    test "with lower bits that are masked off" do
      block = Block.parse!("192.168.100.14/24")

      for member <- 0..255 do
        assert Block.member?(block, BitwiseIp.encode({192, 168, 100, member}))
      end
    end

    test "against IPv6" do
      block = Block.parse!("0.0.0.0/0")
      refute Block.member?(block, BitwiseIp.encode(ipv6()))
    end
  end

  describe "IPv6 membership" do
    test "inside block" do
      block = Block.parse!("1111:2222:3333:4444:5555:6666:7777:8800/120")

      for member <- 0x8800..0x88FF do
        assert Block.member?(block, BitwiseIp.encode({0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, member}))
      end
    end

    test "outside block" do
      block = Block.parse!("1111:2222:3333:4444:5555:6666:7777:8800/120")
      refute Block.member?(block, BitwiseIp.encode({0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x87FF}))
      refute Block.member?(block, BitwiseIp.encode({0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8900}))
    end

    test "with full-length prefix" do
      block = Block.parse!("::1/128")
      refute Block.member?(block, BitwiseIp.encode({0, 0, 0, 0, 0, 0, 0, 0}))
      assert Block.member?(block, BitwiseIp.encode({0, 0, 0, 0, 0, 0, 0, 1}))
      refute Block.member?(block, BitwiseIp.encode({0, 0, 0, 0, 0, 0, 0, 2}))
    end

    test "with zero-length prefix" do
      block = Block.parse!("::/0")
      assert Block.member?(block, BitwiseIp.encode(ipv6()))
    end

    test "with lower bits that are masked off" do
      block = Block.parse!("a:b:c:d:e:f::/48")
      {_, _, _, d, e, f, g, h} = ipv6()
      assert Block.member?(block, BitwiseIp.encode({0x000A, 0x000B, 0x000C, d, e, f, g, h}))
    end

    test "against IPv4" do
      block = Block.parse!("::/0")
      refute Block.member?(block, BitwiseIp.encode(ipv4()))
    end
  end

  describe "IPv4 subnets" do
    test "subset" do
      ip = ipv4() |> as_string()
      a = Block.parse!("#{ip}/3")
      b = Block.parse!("#{ip}/14")
      assert Block.subnet?(a, b)
    end

    test "superset" do
      ip = ipv4() |> as_string()
      a = Block.parse!("#{ip}/15")
      b = Block.parse!("#{ip}/9")
      refute Block.subnet?(a, b)
    end

    test "equivalent" do
      ip = ipv4() |> as_string()
      a = Block.parse!("#{ip}/26")
      assert Block.subnet?(a, a)
    end

    test "disjoint" do
      a = Block.parse!("1.2.0.0/16")
      b = Block.parse!("1.3.0.0/16")
      refute Block.subnet?(a, b)
      refute Block.subnet?(b, a)
    end

    test "universal" do
      a = Block.parse!("0.0.0.0/0")
      b = Block.parse!("#{ipv4() |> as_string()}/16")
      assert Block.subnet?(a, b)
      refute Block.subnet?(b, a)
    end

    test "exact" do
      ip = ipv4() |> as_string()
      a = Block.parse!(ip)
      b = Block.parse!("#{ip}/31")
      assert Block.subnet?(a, a)
      refute Block.subnet?(a, b)
      assert Block.subnet?(b, a)
    end

    test "IPv6" do
      a = Block.parse!("0.0.0.0/0")
      b = Block.parse!("::/0")
      refute Block.subnet?(a, b)
    end
  end

  describe "IPv6 subnets" do
    test "subset" do
      ip = ipv6() |> as_string()
      a = Block.parse!("#{ip}/31")
      b = Block.parse!("#{ip}/41")
      assert Block.subnet?(a, b)
    end

    test "superset" do
      ip = ipv6() |> as_string()
      a = Block.parse!("#{ip}/59")
      b = Block.parse!("#{ip}/26")
      refute Block.subnet?(a, b)
    end

    test "equivalent" do
      ip = ipv6() |> as_string()
      a = Block.parse!("#{ip}/53")
      assert Block.subnet?(a, a)
    end

    test "disjoint" do
      a = Block.parse!("1:2::/58")
      b = Block.parse!("1:3::/97")
      refute Block.subnet?(a, b)
      refute Block.subnet?(b, a)
    end

    test "universal" do
      a = Block.parse!("::/0")
      b = Block.parse!("#{ipv6() |> as_string()}/93")
      assert Block.subnet?(a, b)
      refute Block.subnet?(b, a)
    end

    test "exact" do
      ip = ipv6() |> as_string()
      a = Block.parse!(ip)
      b = Block.parse!("#{ip}/23")
      assert Block.subnet?(a, a)
      refute Block.subnet?(a, b)
      assert Block.subnet?(b, a)
    end

    test "IPv4" do
      a = Block.parse!("::/0")
      b = Block.parse!("0.0.0.0/0")
      refute Block.subnet?(a, b)
    end
  end

  describe "enumerable" do
    test "IPv4 membership" do
      assert BitwiseIp.parse!("127.0.0.1") in Block.parse!("127.0.0.0/8")
      assert BitwiseIp.parse!("192.168.0.1") not in Block.parse!("127.0.0.0/8")
      refute BitwiseIp.parse!("::1") in Block.parse!("0.0.0.0/0")
      refute {127, 0, 0, 1} in Block.parse!("127.0.0.0/8")
    end

    test "IPv6 membership" do
      assert BitwiseIp.parse!("f7::12") in Block.parse!("f7::/64")
      assert BitwiseIp.parse!("f9::ff") not in Block.parse!("f7::/64")
      refute BitwiseIp.parse!("127.0.0.1") in Block.parse!("::/0")
      refute {0, 0, 0, 0, 0, 0, 0, 1} in Block.parse!("::1/128")
    end

    test "count IPv4" do
      for mask <- 0..32 do
        count = :math.pow(2, 32 - mask)
        assert Block.parse!("1.2.3.4/#{mask}") |> Enum.count() == count
      end
    end

    test "count IPv6" do
      for mask <- 0..128 do
        count = :math.pow(2, 128 - mask)
        assert Block.parse!("::/#{mask}") |> Enum.count() == count
      end
    end

    test "slice IPv4" do
      block = Block.parse!("1.2.3.0/29")

      assert Enum.at(block, 0) == BitwiseIp.parse!("1.2.3.0")
      assert Enum.at(block, 1) == BitwiseIp.parse!("1.2.3.1")
      assert Enum.at(block, 2) == BitwiseIp.parse!("1.2.3.2")
      assert Enum.at(block, 3) == BitwiseIp.parse!("1.2.3.3")
      assert Enum.at(block, 4) == BitwiseIp.parse!("1.2.3.4")
      assert Enum.at(block, 5) == BitwiseIp.parse!("1.2.3.5")
      assert Enum.at(block, 6) == BitwiseIp.parse!("1.2.3.6")
      assert Enum.at(block, 7) == BitwiseIp.parse!("1.2.3.7")
      assert Enum.at(block, 8) == nil

      assert Enum.slice(block, 3..5) == [
               BitwiseIp.parse!("1.2.3.3"),
               BitwiseIp.parse!("1.2.3.4"),
               BitwiseIp.parse!("1.2.3.5")
             ]

      assert Enum.slice(block, 3..7//2) == [
               BitwiseIp.parse!("1.2.3.3"),
               BitwiseIp.parse!("1.2.3.5"),
               BitwiseIp.parse!("1.2.3.7")
             ]

      assert Enum.slice(block, 0..10//3) == [
               BitwiseIp.parse!("1.2.3.0"),
               BitwiseIp.parse!("1.2.3.3"),
               BitwiseIp.parse!("1.2.3.6")
             ]
    end

    test "slice IPv6" do
      block = Block.parse!("a:b:c:d:e:f:7::/125")

      assert Enum.at(block, 0) == BitwiseIp.parse!("a:b:c:d:e:f:7:0")
      assert Enum.at(block, 1) == BitwiseIp.parse!("a:b:c:d:e:f:7:1")
      assert Enum.at(block, 2) == BitwiseIp.parse!("a:b:c:d:e:f:7:2")
      assert Enum.at(block, 3) == BitwiseIp.parse!("a:b:c:d:e:f:7:3")
      assert Enum.at(block, 4) == BitwiseIp.parse!("a:b:c:d:e:f:7:4")
      assert Enum.at(block, 5) == BitwiseIp.parse!("a:b:c:d:e:f:7:5")
      assert Enum.at(block, 6) == BitwiseIp.parse!("a:b:c:d:e:f:7:6")
      assert Enum.at(block, 7) == BitwiseIp.parse!("a:b:c:d:e:f:7:7")
      assert Enum.at(block, 8) == nil

      assert Enum.slice(block, 3..5) == [
               BitwiseIp.parse!("a:b:c:d:e:f:7:3"),
               BitwiseIp.parse!("a:b:c:d:e:f:7:4"),
               BitwiseIp.parse!("a:b:c:d:e:f:7:5")
             ]

      assert Enum.slice(block, 3..7//2) == [
               BitwiseIp.parse!("a:b:c:d:e:f:7:3"),
               BitwiseIp.parse!("a:b:c:d:e:f:7:5"),
               BitwiseIp.parse!("a:b:c:d:e:f:7:7")
             ]

      assert Enum.slice(block, 0..10//3) == [
               BitwiseIp.parse!("a:b:c:d:e:f:7:0"),
               BitwiseIp.parse!("a:b:c:d:e:f:7:3"),
               BitwiseIp.parse!("a:b:c:d:e:f:7:6")
             ]
    end

    def reducer(ip, acc) do
      case ip.addr do
        2 -> {:suspend, acc ++ [to_string(ip)]}
        4 -> {:halt, acc ++ [to_string(ip)]}
        _ -> {:cont, acc ++ [to_string(ip)]}
      end
    end

    test "reduce IPv4" do
      block = Block.parse!("0.0.0.0/0")

      {:suspended, acc, cont} = Enumerable.reduce(block, {:cont, []}, &reducer/2)
      assert acc == ["0.0.0.0", "0.0.0.1", "0.0.0.2"]

      {:halted, acc} = cont.({:cont, acc})
      assert acc == ["0.0.0.0", "0.0.0.1", "0.0.0.2", "0.0.0.3", "0.0.0.4"]
    end

    test "reduce IPv6" do
      block = Block.parse!("::/0")

      {:suspended, acc, cont} = Enumerable.reduce(block, {:cont, []}, &reducer/2)
      assert acc == ["::", "::1", "::0.0.0.2"]

      {:halted, acc} = cont.({:cont, acc})
      assert acc == ["::", "::1", "::0.0.0.2", "::0.0.0.3", "::0.0.0.4"]
    end
  end
end
