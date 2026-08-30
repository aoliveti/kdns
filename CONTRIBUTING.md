# Contributing to KDNS

Thank you for your interest in contributing! KDNS is an open-source educational project built to explore high-performance DNS serving, zero-allocation radix trees, and modern Go idioms.

Contributions, ideas, bug reports, and discussions are very welcome.

---

## Development Setup

- **Go Version:** Go 1.27+
- **Linter:** `golangci-lint` (runs 29 linters configured via `.golangci.yml`)

### Useful Commands

```bash
# Run all tests with race detector
go test -race -count=1 ./...

# Run all linters
golangci-lint run ./...

# Run benchmarks
go test -bench=. -benchmem ./...

# Build the binary
go build ./cmd/kdns
```

---

## Code Guidelines & Project Style

To keep the codebase maintainable and consistent:

1. **Keep the Happy Path on the Left Margin**: Use early returns and guard clauses (`if err != nil { return ... }`). Avoid `else` and `else if` chains.
2. **Zero-Allocation Hot Path**: Strive to minimize heap allocations during DNS query resolution and wire parsing (using pooled buffers via `sync.Pool`, stack allocations, and pre-rendered byte slices).
3. **Standard Declaration Ordering**: Keep file declarations ordered: package docstring $\to$ imports $\to$ consts $\to$ vars $\to$ types/methods $\to$ helper functions.
4. **Scope-Driven Naming**: Keep variable names short and natural in tight loops (`q`, `r`, `domain`), and descriptive in wider package scopes.
5. **Testing**:
   - Unit tests go in `*_test.go`
   - Benchmarks go in `*_bench_test.go`
   - Fuzz tests go in `*_fuzz_test.go`
   - Use `testing/synctest` for time-dependent logic without sleeping in real time.

---

## Pull Request Process

1. Fork the repo and create your branch from `main`.
2. Ensure tests pass cleanly with race detection: `go test -race -count=1 ./...`.
3. Ensure linters pass with 0 issues: `golangci-lint run ./...`.
4. Open a Pull Request with a clear description of the change.
