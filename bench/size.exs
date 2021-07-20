defmodule Compile do
  use Bitwise
  alias BitwiseIp.Block

  for mask <- 0..32, mask = BitwiseIp.Mask.encode(:v4, mask) do
    size = :binary.decode_unsigned(<<(~~~mask)::32>>) + 1
    def size(%Block{proto: :v4, mask: unquote(mask)}), do: unquote(size)
  end

  for mask <- 0..128, mask = BitwiseIp.Mask.encode(:v6, mask) do
    size = :binary.decode_unsigned(<<(~~~mask)::128>>) + 1
    def size(%Block{proto: :v6, mask: unquote(mask)}), do: unquote(size)
  end
end

defmodule Run do
  use Bitwise

  def size(%BitwiseIp.Block{proto: :v4, mask: mask}) do
    :binary.decode_unsigned(<<(~~~mask)::32>>) + 1
  end

  def size(%BitwiseIp.Block{proto: :v6, mask: mask}) do
    :binary.decode_unsigned(<<(~~~mask)::128>>) + 1
  end
end

v4 = for mask <- 0..32, do: BitwiseIp.Block.parse!("1.2.3.4/#{mask}")
v6 = for mask <- 0..128, do: BitwiseIp.Block.parse!("::/#{mask}")

blocks = v4 ++ v6

suite = %{
  run: fn -> Enum.each(blocks, &Run.size/1) end,
  compile: fn -> Enum.each(blocks, &Compile.size/1) end,
}

formatters = [
  {Benchee.Formatters.HTML, file: "tmp/size.html", auto_open: false},
  Benchee.Formatters.Console,
]

Benchee.run(suite, formatters: formatters)
