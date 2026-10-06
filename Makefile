GO      ?= go
BIN     := bin/vulndb
DB      ?= vulndb.sqlite
FIXTURE := testdata/fixtures/synthetic.json

.PHONY: all build test test-short cover bench vet fmt fixture-db clean

all: vet test build

# CGO is not needed (pure-Go SQLite driver), so the binary is static and
# cross-compiles with GOOS/GOARCH.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN) ./cmd/vulndb

test:
	$(GO) test ./...

# Skips the test that builds the binary.
test-short:
	$(GO) test -short ./...

cover:
	$(GO) test -cover ./...

# Builds a ~100k CVE / ~500k rule synthetic database first (takes ~30s).
bench:
	$(GO) test -run '^$$' -bench . -benchtime 20x ./internal/matcher/

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal schema

# Create (or replace) a database loaded with the SYNTHETIC fixture.
fixture-db: build
	$(BIN) --db $(DB) db init --fixture $(FIXTURE) --force

clean:
	rm -rf bin
