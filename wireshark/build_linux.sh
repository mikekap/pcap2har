#!/bin/bash
set -exo pipefail

docker buildx build --platform=linux/amd64 -t wireshark-amd64 .

# Copy artifacts to ./wireshark-out on your host
mkdir -p wireshark-out
docker run --rm -v "$PWD/wireshark-out:/host-out" wireshark-amd64 \
  bash -lc 'cp -a /out/* /host-out/ && ls -la /host-out'

