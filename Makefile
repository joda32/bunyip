GO      ?= go
PYTHON  ?= .venv/bin/python
BIN     := bin/vulndb
DB      ?= vulndb.sqlite
FIXTURE := testdata/fixtures/synthetic.json

.PHONY: all build test test-short test-all cover bench vet fmt fixture-db venv updater-test real-db clean

all: vet test build

# CGO is not needed (pure-Go SQLite driver), so the binary is static and
# cross-compiles with GOOS/GOARCH.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(BIN) ./cmd/vulndb

test:
	$(GO) test ./...

# Go and Python suites; the Python suite includes the end-to-end test that
# builds a database from testdata/nvd and queries it with the Go binary.
test-all: test updater-test

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

# Python environment for the updater (stdlib-only package + pytest).
venv:
	python3 -m venv .venv
	$(PYTHON) -m pip install -q -e 'updater[dev]'

updater-test:
	cd updater && GO=$(shell command -v $(GO)) ../$(PYTHON) -m pytest -q

# Build a REAL database from NVD + CISA KEV (needs Internet access). Feeds are
# cached in .cache/feeds and only re-downloaded when NVD publishes changes.
real-db:
	$(PYTHON) -m vulndb_update build --out $(DB) --cache .cache/feeds

clean:
	rm -rf bin
