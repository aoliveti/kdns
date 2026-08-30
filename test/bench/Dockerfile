FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends dnsperf && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["dnsperf"]
