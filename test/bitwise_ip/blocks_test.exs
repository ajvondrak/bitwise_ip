defmodule BitwiseIp.BlocksTest do
  use ExUnit.Case, async: true
  doctest BitwiseIp.Blocks
  alias BitwiseIp.Blocks

  @reserved ~w[
    127.0.0.0/8
    ::1/128
    fc00::/7
    10.0.0.0/8
    172.16.0.0/12
    192.168.0.0/16
  ]

  describe "contain?/2" do
    test "with a %BitwiseIp{}" do
      blocks = Blocks.parse!(@reserved)

      assert Blocks.contain?(blocks, BitwiseIp.parse!("127.0.0.1"))
      assert Blocks.contain?(blocks, BitwiseIp.parse!("::1"))
      assert Blocks.contain?(blocks, BitwiseIp.parse!("fc12::"))
      assert Blocks.contain?(blocks, BitwiseIp.parse!("10.20.30.40"))
      assert Blocks.contain?(blocks, BitwiseIp.parse!("172.16.10.1"))
      assert Blocks.contain?(blocks, BitwiseIp.parse!("192.168.0.1"))

      refute Blocks.contain?(blocks, BitwiseIp.parse!("1.2.3.4"))
      refute Blocks.contain?(blocks, BitwiseIp.parse!("::2"))
      refute Blocks.contain?(blocks, BitwiseIp.parse!("f7::12"))
      refute Blocks.contain?(blocks, BitwiseIp.parse!("11.0.0.1"))
      refute Blocks.contain?(blocks, BitwiseIp.parse!("172.168.0.1"))
      refute Blocks.contain?(blocks, BitwiseIp.parse!("192.16.10.1"))
    end

    test "with an :inet.ip_address()" do
      blocks = Blocks.parse!(@reserved)

      assert Blocks.contain?(blocks, {127, 0, 0, 1})
      assert Blocks.contain?(blocks, {0, 0, 0, 0, 0, 0, 0, 1})
      assert Blocks.contain?(blocks, {0xFC12, 0, 0, 0, 0, 0, 0, 0})
      assert Blocks.contain?(blocks, {10, 20, 30, 40})
      assert Blocks.contain?(blocks, {172, 16, 10, 1})
      assert Blocks.contain?(blocks, {192, 168, 0, 1})

      refute Blocks.contain?(blocks, {1, 2, 3, 4})
      refute Blocks.contain?(blocks, {0, 0, 0, 0, 0, 0, 0, 2})
      refute Blocks.contain?(blocks, {0xF700, 0, 0, 0, 0, 0, 0, 0x0012})
      refute Blocks.contain?(blocks, {11, 0, 0, 1})
      refute Blocks.contain?(blocks, {172, 168, 0, 1})
      refute Blocks.contain?(blocks, {192, 16, 10, 1})
    end
  end

  test "parse!/1" do
    cidrs = ~w[3.14.15.92/6 31:41:59:26::/53]
    valid = ~w[0.0.0.0/6 31:41:59::/53]
    assert Blocks.parse!(cidrs) |> Enum.map(&to_string/1) == valid

    cidrs = ~w[1.2.3.4/5 3.14.15.92/65 6:7:8:9::/10 f7::u/12]
    assert_raise ArgumentError, fn -> Blocks.parse!(cidrs) end
  end

  test "parse/1" do
    cidrs = ~w[1.2.3.4/5 3.14.15.92/65 6:7:8:9::/10 f7::u/12]
    valid = ~w[0.0.0.0/5 ::/10]
    assert Blocks.parse(cidrs) |> Enum.map(&to_string/1) == valid
  end

  describe "optimize/1" do
    test "unmergeable blocks" do
      blocks = Blocks.parse!(["1.2.3.4/16", "2.3.4.5/16"])
      assert Blocks.optimize(blocks) == blocks
    end

    test "mergeable blocks" do
      blocks = Blocks.parse!(["1.2.3.4/16", "1.2.3.4/24"])
      assert Blocks.optimize(blocks) == Blocks.parse!(["1.2.3.4/16"])
    end

    test "fixpoint iteration" do
      blocks =
        Blocks.parse!(~w[
          1::/16
          2::/16
          2:2::/32
          3.0.0.0/8
          3.3.0.0/16
          3.3.3.0/24
          4.0.0.0/8
          4.4.0.0/16
          4.4.4.0/24
          4.4.4.4/32
        ])
        |> Enum.shuffle()
        |> Blocks.optimize()
        |> Enum.map(&to_string/1)
        |> Enum.sort()

      assert blocks == ~w[1::/16 2::/16 3.0.0.0/8 4.0.0.0/8]
    end
  end
end
