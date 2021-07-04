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
      BitwiseIp.Block.contains?(a, b) -> {:success, [a | unvisited] ++ visited}
      BitwiseIp.Block.contains?(b, a) -> {:success, [b | unvisited] ++ visited}
      true -> try_to_merge(a, unvisited, [b | visited])
    end
  end

  defp try_to_merge(_, [], _) do
    :failure
  end
end
