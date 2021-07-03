defmodule BitwiseIpTest do
  use ExUnit.Case, async: true
  doctest BitwiseIp

  describe "IPv4" do
    test "parse/1" do
      assert {:error, _} = BitwiseIp.parse("3.14")

      assert {:ok, ip} = BitwiseIp.parse("192.168.0.1")
      assert ip.protocol == :v4
      assert ip.address == :binary.decode_unsigned(<<192, 168, 0, 1>>)
    end

    test "parse!/1" do
      {:ok, success} = BitwiseIp.parse("127.0.0.1")
      assert BitwiseIp.parse!("127.0.0.1") == success

      {:error, error} = BitwiseIp.parse("127001")
      assert_raise ArgumentError, error, fn -> BitwiseIp.parse!("127001") end
    end

    test "encode/1" do
      ip = BitwiseIp.encode({3, 14, 15, 92})
      assert ip.protocol == :v4
      assert ip.address == :binary.decode_unsigned(<<3, 14, 15, 92>>)
    end

    test "decode/1" do
      address = :binary.decode_unsigned(<<3, 14, 15, 92>>)
      ip = %BitwiseIp{protocol: :v4, address: address}
      assert BitwiseIp.decode(ip) == {3, 14, 15, 92}
    end

    test "to_string/1" do
      octets = Stream.repeatedly(fn -> Enum.random(0..255) end) |> Enum.take(4)
      ip = octets |> Enum.join(".")
      assert BitwiseIp.parse!(ip) |> to_string() == ip
    end
  end

  describe "IPv6" do
    test "parse/1" do
      assert {:error, _} = BitwiseIp.parse("a::g")

      assert {:ok, ip} = BitwiseIp.parse("a::f")
      assert ip.protocol == :v6
      assert ip.address == :binary.decode_unsigned(<<0x000A::16, 0::16, 0::16, 0::16, 0::16, 0::16, 0::16, 0x000F::16>>)
    end

    test "parse!/1" do
      {:ok, success} = BitwiseIp.parse("a:1:b:2:c:3::")
      assert BitwiseIp.parse!("a:1:b:2:c:3::") == success

      {:error, error} = BitwiseIp.parse("1::2::3")
      assert_raise ArgumentError, error, fn -> BitwiseIp.parse!("1::2::3") end
    end

    test "encode/1" do
      ip = BitwiseIp.encode({3, 14, 15, 92, 65, 35, 89, 79})
      assert ip.protocol == :v6
      assert ip.address == :binary.decode_unsigned(<<3::16, 14::16, 15::16, 92::16, 65::16, 35::16, 89::16, 79::16>>)
    end

    test "decode/1" do
      address = :binary.decode_unsigned(<<3::16, 14::16, 15::16, 92::16, 65::16, 35::16, 89::16, 79::16>>)
      ip = %BitwiseIp{protocol: :v6, address: address}
      assert BitwiseIp.decode(ip) == {3, 14, 15, 92, 65, 35, 89, 79}
    end

    test "to_string/1" do
      hextets = Stream.repeatedly(fn -> Enum.random(0..65_535) end) |> Enum.take(8)
      ip = hextets |> Enum.map(&Integer.to_string(&1, 16)) |> Enum.join(":")
      assert String.downcase(BitwiseIp.parse!(ip) |> to_string()) == String.downcase(ip)
    end
  end
end
