set terminal png size 640,480

set output "packet_count_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Number of Packets"
plot ARG1 using 1:2 title 'Packets' with lines lw 2

set output "bytes_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Number of Bytes"
plot ARG1 using 1:3 title 'Bytes' with lines lw 2

set output "ipv4_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Number of IPv4"
plot ARG1 using 1:4 title 'IPv4' with lines lw 3

set output "arp_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Number of ARP"
plot ARG1 using 1:5 title 'ARP' with lines lw 3

set output "tcp_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Number of TCP"
plot ARG1 using 1:6 title 'TCP' with lines lw 3

set output "udp_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Number of UDP"
plot ARG1 using 1:7 title 'UDP' with lines lw 3

set output "icmp_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Number of ICMP"
plot ARG1 using 1:8 title 'ICMP' with lines lw 3

set output "http_time_series.png"
set xlabel "Time (seconds)"
set ylabel "Number of HTTP"
plot ARG1 using 1:9 title 'HTTP' with lines lw 3