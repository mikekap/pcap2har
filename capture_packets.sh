#!/bin/bash
set -mexo pipefail

sudo /bin/bash -c 'echo hi';
sudo tcpdump -w capture.pcap -s 0 -i any tcp port 80 or tcp port 443 or udp port 443 &
SSLKEYLOGFILE=/tmp/sslkeylog.log /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --user-data-dir=/tmp/prof --no-first-run "$@"
kill -s SIGINT %1
fg
rm capture.pcapng
editcap --inject-secrets tls,/tmp/sslkeylog.log capture.pcap capture.pcapng
rm -f /tmp/sslkeylog.log capture.pcap
