GO ?= go
BIN_DIR ?= bin
DIST_DIR ?= dist
FUZZ_TIME ?= 10s

.DEFAULT_GOAL := help

.PHONY: help test test-race vet check build check-config release fuzz fuzz-lease fuzz-arp fuzz-state

help:
	@echo "Available targets:"
	@echo "  test          Run all unit and integration tests"
	@echo "  test-race     Run all tests with the race detector"
	@echo "  vet           Run go vet"
	@echo "  check         Run test, test-race, and vet"
	@echo "  build         Build the collector into $(BIN_DIR)"
	@echo "  check-config  Validate config.example.json"
	@echo "  fuzz          Run all parser and state fuzz targets"
	@echo "  release       Build release archives (requires VERSION=vX.Y.Z)"

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

check: test test-race vet

build:
	mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BIN_DIR)/dhcp-lease-observer ./cmd/dhcp-lease-observer

check-config:
	$(GO) run ./cmd/dhcp-lease-observer --config ./config.example.json --check-config

release:
	@test -n "$(VERSION)" || (echo "VERSION is required, for example: make release VERSION=v0.1.0" >&2; exit 2)
	$(GO) run ./cmd/package-release --version $(VERSION) --output-dir $(DIST_DIR)

fuzz: fuzz-lease fuzz-arp fuzz-state

fuzz-lease:
	$(GO) test ./internal/parser/ix2106 -run '^$$' -fuzz '^FuzzParseLease$$' -fuzztime $(FUZZ_TIME)

fuzz-arp:
	$(GO) test ./internal/parser/ix2106 -run '^$$' -fuzz '^FuzzParseARP$$' -fuzztime $(FUZZ_TIME)

fuzz-state:
	$(GO) test ./internal/state -run '^$$' -fuzz '^FuzzDiff$$' -fuzztime $(FUZZ_TIME)
