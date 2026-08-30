BINARY_NAME := kdns
BUILD_DIR := bin
GO := go

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

DOCKER_ARCH ?= $(shell $(GO) env GOARCH 2>/dev/null || echo "amd64")
PLATFORM ?= linux/$(DOCKER_ARCH)

API_TOKEN ?=
MODE ?= standalone

DEV_PORT_DNS ?= 1053
DEV_PORT_DOT ?= 8853
DEV_PORT_DOH ?= 8443
DEV_PORT_HTTP ?= 8080
DEV_PORT_CLUSTER ?= 8081
DEV_VOLUME ?= kdns_data:/data

LDFLAGS := -s -w \
	-X 'main.version=$(VERSION)' \
	-X 'main.commit=$(COMMIT)' \
	-X 'main.buildTime=$(BUILD_TIME)'

.PHONY: all help build build-debug run test test-cover bench fuzz lint fmt clean docker-build docker-dev test-e2e bench-dnsperf

all: build

## help: Show available commands
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'

## build: Build static binary into bin/
build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/kdns

## run: Build and run server locally
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

## build-debug: Build binary with pprof endpoints enabled (-tags pprof)
build-debug:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -tags pprof -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-debug ./cmd/kdns

## test: Run unit tests with race detector
test:
	$(GO) test -v -race -count=1 ./...

## test-integration: Run native Go integration tests (Standalone, Hub, Replica)
test-integration:
	$(GO) test -v -race -count=1 ./test/integration/...

## test-cover: Run unit tests and generate HTML coverage report
test-cover:
	@mkdir -p coverage
	$(GO) test -v -race -coverprofile=coverage/coverage.out ./...
	$(GO) tool cover -html=coverage/coverage.out -o coverage/coverage.html

## bench: Run memory and CPU benchmark tests
bench:
	$(GO) test -v -bench=. -benchmem -run=^$$ ./...

FUZZTIME ?= 100000x

## fuzz: Run fuzz test battery (100k iterations per target)
fuzz:
	$(GO) test -timeout=0 -fuzz=FuzzDecoder_ReadRecord -fuzztime=$(FUZZTIME) ./internal/codec
	$(GO) test -timeout=0 -fuzz=FuzzEncoder_WriteRecord -fuzztime=$(FUZZTIME) ./internal/codec
	$(GO) test -timeout=0 -fuzz=FuzzMessage_Unpack -fuzztime=$(FUZZTIME) ./internal/dns
	$(GO) test -timeout=0 -fuzz=FuzzMessage_PackResponse -fuzztime=$(FUZZTIME) ./internal/dns
	$(GO) test -timeout=0 -fuzz=FuzzDomainIterator -fuzztime=$(FUZZTIME) ./internal/radix
	$(GO) test -timeout=0 -fuzz=FuzzTree_Operations -fuzztime=$(FUZZTIME) ./internal/radix
	$(GO) test -timeout=0 -fuzz=FuzzLimiter_Check -fuzztime=$(FUZZTIME) ./internal/rrl
	$(GO) test -timeout=0 -fuzz=FuzzSnapshot_Load -fuzztime=$(FUZZTIME) ./internal/snapshot
	$(GO) test -timeout=0 -fuzz=FuzzStore_OpenWithCorruptedSnapshot -fuzztime=$(FUZZTIME) ./internal/store
	$(GO) test -timeout=0 -fuzz=FuzzWAL_Replay -fuzztime=$(FUZZTIME) ./internal/wal
	$(GO) test -timeout=0 -fuzz=FuzzZone_Parse -fuzztime=$(FUZZTIME) ./internal/zone
	$(GO) test -timeout=0 -fuzz=FuzzAPI_UpsertPayload -fuzztime=$(FUZZTIME) ./internal/api
	$(GO) test -timeout=0 -fuzz=FuzzRFC2136_Process -fuzztime=$(FUZZTIME) ./internal/rfc2136
	$(GO) test -timeout=0 -fuzz=FuzzTSIG_Extract -fuzztime=$(FUZZTIME) ./internal/tsig

## lint: Run golangci-lint check
lint:
	golangci-lint run ./...

## fmt: Format codebase with gofmt
fmt:
	$(GO) fmt ./...

## clean: Remove build artifacts and coverage files
clean:
	rm -rf $(BUILD_DIR) coverage

## docker-build: Build Docker image for local host platform
docker-build:
	@mkdir -p $(BUILD_DIR)/linux/$(DOCKER_ARCH)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(DOCKER_ARCH) $(GO) build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/linux/$(DOCKER_ARCH)/$(BINARY_NAME) ./cmd/kdns
	docker buildx build \
		-f build/package/Dockerfile \
		--platform $(PLATFORM) \
		-t $(BINARY_NAME):latest --load $(BUILD_DIR)

## docker-dev: Run container locally in development mode on non-privileged ports (requires API_TOKEN=<secret>)
docker-dev:
	@if [ -z "$(API_TOKEN)" ]; then \
		echo "❌ Error: API_TOKEN is required to run KDNS in development mode."; \
		echo "   Usage: make docker-dev API_TOKEN=<your-secret-token>"; \
		echo "   Or:    export API_TOKEN=<your-secret-token> && make docker-dev"; \
		exit 1; \
	fi
	docker run -d \
		--name $(BINARY_NAME)-dev \
		-p $(DEV_PORT_DNS):5353/udp \
		-p $(DEV_PORT_DNS):5353/tcp \
		-p $(DEV_PORT_DOT):853/tcp \
		-p $(DEV_PORT_DOH):8443/tcp \
		-p $(DEV_PORT_HTTP):8080/tcp \
		-p $(DEV_PORT_CLUSTER):8081/tcp \
		-e KDNS_MODE="$(MODE)" \
		-e KDNS_API_TOKEN="$(API_TOKEN)" \
		-v $(DEV_VOLUME) \
		--read-only \
		--cap-drop=ALL \
		--security-opt=no-new-privileges:true \
		$(BINARY_NAME):latest

## test-e2e: Run Docker Compose multi-node cluster and execute hermetic smoke test runner
test-e2e: docker-build
	docker compose -f test/e2e/docker-compose.yml up -d --build
	@sleep 2
	docker compose -f test/e2e/docker-compose.yml run --rm e2e-runner
	docker compose -f test/e2e/docker-compose.yml down -v

## bench-dnsperf: Run high-throughput performance benchmark with dnsperf in Docker
bench-dnsperf: docker-build
	@mkdir -p benchmarks
	docker build -t kdns-bench:latest -f test/bench/Dockerfile .
	KDNS_ZONE_FILE=/bench/benchmark.zone KDNS_RRL=false docker compose -f test/e2e/docker-compose.yml up -d --build kdns-standalone
	@sleep 2
	@echo "==> Running dnsperf benchmark (10s @ 20 concurrency)..."
	@docker run --rm --network e2e_default \
		-v "$$(PWD)/test/bench:/bench:ro" \
		kdns-bench:latest \
		-s kdns-standalone -p 5353 \
		-d /bench/queries.txt \
		-c 20 -l 10 | tee benchmarks/dnsperf.log
	@echo "" | tee -a benchmarks/dnsperf.log
	@echo "===================================================================" | tee -a benchmarks/dnsperf.log
	@echo "             KDNS PROMETHEUS METRICS (/metrics via curl)" | tee -a benchmarks/dnsperf.log
	@echo "===================================================================" | tee -a benchmarks/dnsperf.log
	@curl -s http://localhost:8083/metrics | grep -E '^kdns_queries_by_type_total|^kdns_responses_total|^kdns_cache_hits|^kdns_cache_misses' | tee -a benchmarks/dnsperf.log
	@echo "===================================================================" | tee -a benchmarks/dnsperf.log
	docker compose -f test/e2e/docker-compose.yml down -v
	@echo "==> Benchmark results saved to benchmarks/dnsperf.log and all containers stopped."