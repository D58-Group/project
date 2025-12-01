set output "packets_time_series.png"

plot "stats.txt" using 1:2 title  'Packets' with lines,
      "stats.txt" using 1:3 title  'Bytes' with lines,
      "stats.txt" using 1:4 title  'IPv4' with lines,
      "stats.txt" using 1:5 title  'ARP' with lines,
      "stats.txt" using 1:6 title  'TCP' with lines,
      "stats.txt" using 1:7 title  'UDP' with lines,
      "stats.txt" using 1:8 title  'ICMP' with lines,
      "stats.txt" using 1:9 title  'HTTP' with lines,