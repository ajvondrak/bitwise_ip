Bench.Inputs.seed

cidrs = Bench.Inputs.cidrs(1_000)

suite = %{
  ip: fn -> Enum.each(cidrs, &IP.Prefix.from_string!/1) end,
  bitwise_ip: fn -> Enum.each(cidrs, &BitwiseIp.Block.parse!/1) end,
  inet_cidr: fn -> Enum.each(cidrs, &InetCidr.parse(&1, true)) end,
  cider: fn -> Enum.each(cidrs, &Cider.parse/1) end,
  cidr: fn -> Enum.each(cidrs, &CIDR.parse/1) end,
}

formatters = [
  {Benchee.Formatters.HTML, file: "tmp/parse.html", auto_open: false},
  Benchee.Formatters.Console,
]

Benchee.run(suite, formatters: formatters)
