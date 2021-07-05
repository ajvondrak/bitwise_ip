defmodule BitwiseIp.Block do
  use Bitwise

  defstruct [:prefix, :mask]

  def member?(block, ip) do
    ip.protocol == block.prefix.protocol &&
      (ip.address &&& block.mask) == block.prefix.address
  end

  def contains?(sup, sub) do
    sup.mask <= sub.mask && member?(sup, sub.prefix)
  end

  def parse!(cidr) do
    case parse(cidr) do
      {:ok, block} -> block
      {:error, message} -> raise ArgumentError, message
    end
  end

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
         {:ok, mask} <- BitwiseIp.Mask.parse(ip.protocol, mask) do
      prefix = %{ip | address: ip.address &&& mask}
      {:ok, %BitwiseIp.Block{prefix: prefix, mask: mask}}
    end
  end

  @v4 BitwiseIp.Mask.encode(:v4, 32)
  @v6 BitwiseIp.Mask.encode(:v6, 128)

  defp parse_without_mask(ip) do
    with {:ok, ip} <- BitwiseIp.parse(ip) do
      case ip.protocol do
        :v4 -> {:ok, %BitwiseIp.Block{prefix: ip, mask: @v4}}
        :v6 -> {:ok, %BitwiseIp.Block{prefix: ip, mask: @v6}}
      end
    end
  end

  defimpl String.Chars do
    def to_string(block) do
      mask = BitwiseIp.Mask.decode(block.prefix.protocol, block.mask)
      "#{block.prefix}/#{mask}"
    end
  end

  defimpl Enumerable do
    def member?(block, %BitwiseIp{} = ip) do
      {:ok, BitwiseIp.Block.member?(block, ip)}
    end

    def member?(_, _) do
      {:ok, false}
    end

    def count(block) do
      case block.prefix.protocol do
        :v4 -> {:ok, :binary.decode_unsigned(<<(~~~block.mask)::32>>) + 1}
        :v6 -> {:ok, :binary.decode_unsigned(<<(~~~block.mask)::128>>) + 1}
      end
    end

    def slice(block) do
      with {:ok, size} <- count(block) do
        first = block.prefix
        {:ok, size, &slice(%{first | address: first.address + &1}, &2)}
      end
    end

    defp slice(ip, 1) do
      [ip]
    end

    defp slice(ip, length) do
      [ip | slice(%{ip | address: ip.address + 1}, length - 1)]
    end

    def reduce(block, acc, fun) do
      with {:ok, size} <- count(block) do
        first = block.prefix
        last = %{first | address: first.address + size - 1}
        reduce(first, last, acc, fun)
      end
    end

    defp reduce(_first, _last, {:halt, acc}, _fun) do
      {:halted, acc}
    end

    defp reduce(first, last, {:suspend, acc}, fun) do
      {:suspended, acc, &reduce(first, last, &1, fun)}
    end

    defp reduce(first, last, {:cont, acc}, fun) do
      if first.address <= last.address do
        next = %{first | address: first.address + 1}
        reduce(next, last, fun.(first, acc), fun)
      else
        {:done, acc}
      end
    end
  end
end
