defmodule BitwiseIp.Block do
  use Bitwise

  defstruct [:prefix, :mask]

  def member?(
    %BitwiseIp.Block{
      prefix: %BitwiseIp{protocol: protocol, address: net},
      mask: mask
    },
    %BitwiseIp{protocol: protocol, address: ip}
  ) do
    (ip &&& mask) == net
  end

  def member?(_, _) do
    false
  end

  def contains?(sup, sub) do
    sup.mask <= sub.mask && member?(sup, sub.prefix)
  end

  for mask <- 1..32, mask = BitwiseIp.Mask.encode(:v4, mask) do
    size = :binary.decode_unsigned(<<(~~~mask)::32>>) + 1
    def size(block) when block.mask == unquote(mask), do: unquote(size)
  end

  for mask <- 1..128, mask = BitwiseIp.Mask.encode(:v6, mask) do
    size = :binary.decode_unsigned(<<(~~~mask)::128>>) + 1
    def size(block) when block.mask == unquote(mask), do: unquote(size)
  end

  @size_v4 BitwiseIp.Mask.encode(:v4, 32) + 1
  @size_v6 BitwiseIp.Mask.encode(:v6, 128) + 1

  def size(block) when block.mask == 0 do
    case block.prefix.protocol do
      :v4 -> @size_v4
      :v6 -> @size_v6
    end
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

  @mask_v4 BitwiseIp.Mask.encode(:v4, 32)
  @mask_v6 BitwiseIp.Mask.encode(:v6, 128)

  defp parse_without_mask(ip) do
    with {:ok, ip} <- BitwiseIp.parse(ip) do
      case ip.protocol do
        :v4 -> {:ok, %BitwiseIp.Block{prefix: ip, mask: @mask_v4}}
        :v6 -> {:ok, %BitwiseIp.Block{prefix: ip, mask: @mask_v6}}
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
      {:ok, BitwiseIp.Block.size(block)}
    end

    def slice(block) do
      size = BitwiseIp.Block.size(block)
      first = block.prefix
      {:ok, size, &slice(%{first | address: first.address + &1}, &2)}
    end

    defp slice(ip, 1) do
      [ip]
    end

    defp slice(ip, length) do
      [ip | slice(%{ip | address: ip.address + 1}, length - 1)]
    end

    def reduce(block, acc, fun) do
      size = BitwiseIp.Block.size(block)
      first = block.prefix
      last = %{first | address: first.address + size - 1}
      reduce(first, last, acc, fun)
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
