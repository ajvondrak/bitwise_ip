defmodule BitwiseIp.Block do
  use Bitwise

  defstruct [:proto, :addr, :mask]

  alias __MODULE__

  def member?(
        %Block{proto: proto, addr: prefix, mask: mask},
        %BitwiseIp{proto: proto, addr: ip}
      ) do
    prefix == (ip &&& mask)
  end

  def member?(_, _) do
    false
  end

  def contains?(
        %Block{proto: proto, addr: prefix, mask: mask},
        %Block{proto: proto, addr: ip, mask: submask}
      )
      when mask <= submask do
    prefix == (ip &&& mask)
  end

  def contains?(_, _) do
    false
  end

  for mask <- 0..32, mask = BitwiseIp.Mask.encode(:v4, mask) do
    size = :binary.decode_unsigned(<<(~~~mask)::32>>) + 1
    def size(%Block{proto: :v4, mask: unquote(mask)}), do: unquote(size)
  end

  for mask <- 0..128, mask = BitwiseIp.Mask.encode(:v6, mask) do
    size = :binary.decode_unsigned(<<(~~~mask)::128>>) + 1
    def size(%Block{proto: :v6, mask: unquote(mask)}), do: unquote(size)
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
         {:ok, mask} <- BitwiseIp.Mask.parse(ip.proto, mask) do
      {:ok, %Block{proto: ip.proto, addr: ip.addr &&& mask, mask: mask}}
    end
  end

  @v4 BitwiseIp.Mask.encode(:v4, 32)
  @v6 BitwiseIp.Mask.encode(:v6, 128)

  defp parse_without_mask(ip) do
    with {:ok, ip} <- BitwiseIp.parse(ip) do
      case ip.proto do
        :v4 -> {:ok, %Block{proto: :v4, addr: ip.addr, mask: @v4}}
        :v6 -> {:ok, %Block{proto: :v6, addr: ip.addr, mask: @v6}}
      end
    end
  end

  defimpl String.Chars do
    def to_string(block) do
      ip = %BitwiseIp{proto: block.proto, addr: block.addr}
      mask = BitwiseIp.Mask.decode(block.proto, block.mask)
      "#{ip}/#{mask}"
    end
  end

  defimpl Enumerable do
    def member?(block, ip) do
      {:ok, Block.member?(block, ip)}
    end

    def count(block) do
      {:ok, Block.size(block)}
    end

    def slice(%Block{proto: proto, addr: addr} = block) do
      size = Block.size(block)
      {:ok, size, &slice(proto, addr + &1, &2)}
    end

    defp slice(proto, addr, 1) do
      [%BitwiseIp{proto: proto, addr: addr}]
    end

    defp slice(proto, addr, n) do
      [%BitwiseIp{proto: proto, addr: addr} | slice(proto, addr + 1, n - 1)]
    end

    def reduce(%Block{proto: proto, addr: addr} = block, acc, fun) do
      size = Block.size(block)
      reduce(proto, addr, addr + size - 1, acc, fun)
    end

    defp reduce(_proto, _addr, _last, {:halt, acc}, _fun) do
      {:halted, acc}
    end

    defp reduce(proto, addr, last, {:suspend, acc}, fun) do
      {:suspended, acc, &reduce(proto, addr, last, &1, fun)}
    end

    defp reduce(proto, addr, last, {:cont, acc}, fun) do
      if addr <= last do
        ip = %BitwiseIp{proto: proto, addr: addr}
        reduce(proto, addr + 1, last, fun.(ip, acc), fun)
      else
        {:done, acc}
      end
    end
  end
end
