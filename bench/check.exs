Bench.Inputs.seed

ips = Bench.Inputs.ips(1_000)

parsed_ips = %{
  ip: Enum.map(ips, &IP.Address.from_string!(:inet.ntoa(&1) |> to_string())),
  bitwise_ip: Enum.map(ips, &BitwiseIp.encode/1),
  remote_ip: Enum.map(ips, &RemoteIp.Block.encode/1),
  inet_cidr: ips,
  cider: Enum.map(ips, &Cider.ip!/1),
  cidr: ips,
}

cidrs = Bench.Inputs.cidrs(1_000)

parsed_cidrs = %{
  ip: Enum.map(cidrs, &IP.Prefix.from_string!/1),
  bitwise_ip: Enum.map(cidrs, &BitwiseIp.Block.parse!/1),
  remote_ip: Enum.map(cidrs, &RemoteIp.Block.parse!/1),
  inet_cidr: Enum.map(cidrs, &InetCidr.parse(&1, true)),
  cider: Enum.map(cidrs, &Cider.parse/1),
  cidr: Enum.map(cidrs, &CIDR.parse/1),
}

suite = %{
  ip: fn ->
    Enum.each(parsed_ips[:ip], fn ip ->
      Enum.each(parsed_cidrs[:ip], &IP.Prefix.contains_address?(&1, ip))
    end)
  end,
  bitwise_ip: fn ->
    Enum.each(parsed_ips[:bitwise_ip], fn ip ->
      Enum.each(parsed_cidrs[:bitwise_ip], &BitwiseIp.Block.member?(&1, ip))
    end)
  end,
  remote_ip: fn ->
    Enum.each(parsed_ips[:remote_ip], fn ip ->
      Enum.each(parsed_cidrs[:remote_ip], &RemoteIp.Block.contains?(&1, ip))
    end)
  end,
  inet_cidr: fn ->
    Enum.each(parsed_ips[:inet_cidr], fn ip ->
      Enum.each(parsed_cidrs[:inet_cidr], &InetCidr.contains?(&1, ip))
    end)
  end,
  cider: fn ->
    Enum.each(parsed_ips[:cider], fn ip ->
      Enum.each(parsed_cidrs[:cider], &Cider.contains?(ip, &1))
    end)
  end,
  cidr: fn ->
    Enum.each(parsed_ips[:cidr], fn ip ->
      Enum.each(parsed_cidrs[:cidr], &CIDR.match(&1, ip))
    end)
  end,
}

formatters = [
  {Benchee.Formatters.HTML, file: "tmp/check.html", auto_open: false},
  Benchee.Formatters.Console,
]

Benchee.run(suite, formatters: formatters)
