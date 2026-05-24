FROM debian:bookworm-slim

ARG SLIVER_VERSION=v1.7.3
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates locales mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /usr/local/bin/sliver-server \
    "https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-server_linux-amd64" \
    && chmod +x /usr/local/bin/sliver-server \
    && curl -fsSL -o /usr/local/bin/sliver-client \
    "https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-client_linux-amd64" \
    && chmod +x /usr/local/bin/sliver-client

RUN useradd -m -u 1000 sliver
USER sliver
WORKDIR /home/sliver

RUN /usr/local/bin/sliver-server unpack --force

EXPOSE 31337 8443 8888

ENTRYPOINT ["/usr/local/bin/sliver-server"]
CMD ["daemon", "--lhost", "0.0.0.0", "--lport", "31337"]
