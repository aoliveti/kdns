# syntax=docker/dockerfile:1
# Copyright (c) 2026 Andrea Oliveti All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

FROM alpine:3.21 AS prep
RUN mkdir -p /data && chown -R 65532:65532 /data && chmod 750 /data

FROM gcr.io/distroless/static-debian13:nonroot

LABEL org.opencontainers.image.title="KDNS" \
      org.opencontainers.image.description="Authoritative DNS Server" \
      org.opencontainers.image.licenses="BSD-3-Clause" \
      org.opencontainers.image.vendor="Andrea Oliveti" \
      org.opencontainers.image.source="https://github.com/aoliveti/kdns"

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY --from=prep --chown=65532:65532 /data /data
COPY ${TARGETOS}/${TARGETARCH}/kdns /usr/local/bin/kdns

ENV KDNS_ADDRESS=:5353 \
    KDNS_DOH_ADDR=:8443 \
    KDNS_HTTP_ADDR=:8080 \
    KDNS_STORAGE_DIR=/data

USER 65532:65532

VOLUME ["/data"]

EXPOSE 5353/udp 5353/tcp 853/tcp 8443/tcp 8080/tcp 8081/tcp

ENTRYPOINT ["/usr/local/bin/kdns"]
