defmodule Compile do
  import Bitwise

  @v4 0xFFFFFFFF

  for decoded <- 0..32 do
    <<encoded::32>> = <<bnot(bsr(@v4, decoded))::32>>
    def encode(:v4, unquote(decoded)), do: unquote(encoded)
    def decode(:v4, unquote(encoded)), do: unquote(decoded)
    def parse(:v4, unquote(to_string(decoded))), do: {:ok, unquote(encoded)}
  end

  @v6 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

  for decoded <- 0..128 do
    <<encoded::128>> = <<bnot(bsr(@v6, decoded))::128>>
    def encode(:v6, unquote(decoded)), do: unquote(encoded)
    def decode(:v6, unquote(encoded)), do: unquote(decoded)
    def parse(:v6, unquote(to_string(decoded))), do: {:ok, unquote(encoded)}
  end

  def parse(:v4, prefix) do
    {:error, "Invalid IPv4 mask #{inspect(prefix)}"}
  end

  def parse(:v6, prefix) do
    {:error, "Invalid IPv6 mask #{inspect(prefix)}"}
  end
end

defmodule Run do
  import Bitwise

  @v4 0xFFFFFFFF
  @v6 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

  def encode(:v4, decoded) do
    <<encoded::32>> = <<bnot(bsr(@v4, decoded))::32>>
    encoded
  end

  def encode(:v6, decoded) do
    <<encoded::128>> = <<bnot(bsr(@v6, decoded))::128>>
    encoded
  end

  def decode(_proto, mask) do
    ones = for <<1::1 <- :binary.encode_unsigned(mask)>>, do: 1
    length(ones)
  end

  def parse(proto, prefix) do
    encode(proto, String.to_integer(prefix))
  end
end

v4 = Enum.to_list(0..32)
v6 = Enum.to_list(0..128)

suite = %{
  encode_run: fn ->
    Enum.each(v4, &Run.encode(:v4, &1))
    Enum.each(v6, &Run.encode(:v6, &1))
  end,
  encode_compile: fn ->
    Enum.each(v4, &Compile.encode(:v4, &1))
    Enum.each(v6, &Compile.encode(:v6, &1))
  end
}

Benchee.run(suite)

v4 = for mask <- 0..32, do: BitwiseIp.Mask.encode(:v4, mask)
v6 = for mask <- 0..128, do: BitwiseIp.Mask.encode(:v6, mask)

suite = %{
  decode_run: fn ->
    Enum.each(v4, &Run.decode(:v4, &1))
    Enum.each(v6, &Run.decode(:v6, &1))
  end,
  decode_compile: fn ->
    Enum.each(v4, &Compile.decode(:v4, &1))
    Enum.each(v6, &Compile.decode(:v6, &1))
  end
}

Benchee.run(suite)

v4 = for mask <- 0..32, do: Integer.to_string(mask)
v6 = for mask <- 0..128, do: Integer.to_string(mask)

suite = %{
  parse_run: fn ->
    Enum.each(v4, &Run.parse(:v4, &1))
    Enum.each(v6, &Run.parse(:v6, &1))
  end,
  parse_compile: fn ->
    Enum.each(v4, &Compile.parse(:v4, &1))
    Enum.each(v6, &Compile.parse(:v6, &1))
  end
}

Benchee.run(suite)
