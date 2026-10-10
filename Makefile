GO      ?= go
PYTHON  ?= .venv/bin/python
BIN     := bin/vulndb
DB      ?= vulndb.sqlite
FIXTURE := testdata/fixtures/synthetic.json

.PHONY: all build test test-short test-all cover bench vet fmt fixture-db venv updater-test real-db real-db-python keygen bundle release clean

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

# Build a REAL database from the real sources (needs Internet access): NVD +
# CISA KEV + OSV distro advisories + webappanalyzer. The self-contained Go
# binary fetches everything and loads its embedded curated data. Sources are
# cached in .cache/feeds and only re-downloaded when they change.
real-db: build
	$(BIN) --db $(DB) update --cache .cache/feeds

# The Python updater builds the same core tables and is kept as the porting
# oracle and for its curation commands (review-aliases, review-products).
real-db-python:
	$(PYTHON) -m vulndb_update build --out $(DB) --cache .cache/feeds

# Signing key for transport bundles (once; keep the private key on the build machine).
KEY ?= vulndb-signing.key
PUB ?= vulndb-signing.pub
keygen: build
	$(BIN) bundle keygen --key $(KEY) --pub $(PUB)

# Signed transport bundle of $(DB) for the offline side (see docs/deployment.md).
BUNDLE ?= vulndb-$(shell date -u +%F).tar.gz
bundle: build
	$(BIN) --db $(DB) bundle create --key $(KEY) --out $(BUNDLE)

# Build release archives into dist/. Override VERSION (default: git describe)
# and PLATFORMS (space-separated GOOS/GOARCH list, default: host-ish linux/amd64).
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORMS ?= linux/amd64
release:
	scripts/release.sh "$(VERSION)" $(PLATFORMS)

clean:
	rm -rf bin dist
