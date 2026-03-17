FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    make \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY . .

RUN make

# ─────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/ft_nmap .
COPY --from=builder /build/ips-file .

# ft_nmap uses raw sockets; the container must be run with:
#   docker run --cap-add NET_RAW --cap-add NET_ADMIN ...
ENTRYPOINT ["tail", "-f", "/dev/null"]
