FROM alpine:3.21

RUN apk add --no-cache \
    bash \
    curl \
    bind-tools \
    docker-cli \
    docker-cli-compose

WORKDIR /workspace

ENTRYPOINT ["/test/e2e/smoke.sh"]
