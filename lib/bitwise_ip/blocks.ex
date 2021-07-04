defmodule BitwiseIp.Blocks do
  def contain?(blocks, %BitwiseIp{} = ip) do
    Enum.any?(blocks, &BitwiseIp.Block.member?(&1, ip))
  end

  def contain?(blocks, ip) do
    contain?(blocks, BitwiseIp.encode(ip))
  end

  def parse!(cidrs) do
    Enum.map(cidrs, &BitwiseIp.Block.parse!/1)
  end

  def parse([cidr | cidrs]) do
    case BitwiseIp.Block.parse(cidr) do
      {:ok, block} -> [block | parse(cidrs)]
      {:error, _} -> parse(cidrs)
    end
  end

  def parse([]) do
    []
  end
end
