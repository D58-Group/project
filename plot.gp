set terminal png size 640,480

set output "packet_type_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Count"
plot  "stats.txt" using 1:2 title  'Packets' with lines lw 2, \
      "stats.txt" using 1:4 title  'IPv4' with lines lw 2, \
      "stats.txt" using 1:5 title  'ARP' with lines lw 2, \
      "stats.txt" using 1:6 title  'TCP' with lines lw 2, \
      "stats.txt" using 1:7 title  'UDP' with lines lw 2, \
      "stats.txt" using 1:8 title  'ICMP' with lines lw 2, \
      "stats.txt" using 1:9 title  'HTTP' with lines lw 2, \

set output "bytes_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Number of Bytes"
plot  "stats.txt" using 1:3 title  'Bytes' with lines lw 2
