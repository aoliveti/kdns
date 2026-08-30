## Description
<!-- Summary of changes made and technical rationale. -->

## Technical Checklist
- [ ] **Idiomatic Naming:** Scope-driven variable naming, no package name stutter, no data types in identifiers.
- [ ] **Line of Sight:** Happy path aligned to left margin with strict early returns (no `else` / `else if`).
- [ ] **Zero-Allocation Hot Path:** No heap allocations on resolution and wire packing paths.
- [ ] **Test Verification:** Tests added/updated, passing race detector (`go test -race -count=1 ./...`).
- [ ] **Static Analysis:** Clean execution with 0 issues on linter suite (`golangci-lint run ./...`).
- [ ] **Documentation:** Relevant `docs/` and `api/openapi.yaml` contracts updated if endpoints changed.
