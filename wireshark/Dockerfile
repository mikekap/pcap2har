# Build Wireshark for linux/amd64 even when building on Apple Silicon
FROM ubuntu:25.04

ARG DEBIAN_FRONTEND=noninteractive
ARG WIRESHARK_REF=358e2bec36273214c7380e634eeeeff0443286f5

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git curl python3 sudo \
    build-essential cmake ninja-build pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Grab source
WORKDIR /src
RUN git clone --depth=1 https://gitlab.com/mikekap/wireshark.git . && git fetch origin "${WIRESHARK_REF}" && git checkout "${WIRESHARK_REF}"

# Install build deps the Wireshark way (this covers a LOT of optional libs)
# Options:
#   --install-qt5 (Qt5 GUI) or --install-qt6 (Qt6 GUI)
#   --install-optional to pull in extras (lz4, zstd, nghttp2, brotli, etc.)
RUN ./tools/debian-setup.sh --install-optional -y

# Build
RUN cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release -DENABLE_QT=OFF \
 && cmake --build build -j"$(nproc)"

# Install into a clean prefix so you can copy artifacts out easily
RUN cmake --install build --prefix /opt/wireshark

# Keep the image light-ish
RUN strip /opt/wireshark/bin/* || true

# Place binaries in /out for easy volume mount copies
RUN mkdir -p /out && cp -a /opt/wireshark/bin /out/bin && cp -a /opt/wireshark/share /out/share

# Default to shell; you can also set ENTRYPOINT to wireshark/tshark if you prefer
CMD ["/bin/bash"]

