# SPDX-FileCopyrightText: 2026 Scott Friedman
# SPDX-License-Identifier: Apache-2.0

# nitro — AWS Nitro Enclave attestation producer.
#
# The default targets run everywhere (the enclave NSM device read is excluded —
# it requires the `nsm` build tag and a running enclave). `build-nsm` is the
# manual target that compile-checks the device Source on a machine that has no
# enclave; it is run by CI as a compile-only gate, never executed.

GOFLAGS := -trimpath
VERSION ?= dev

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

.PHONY: check
check: fmt vet test ## fmt + vet + test (the default gate)

.PHONY: fmt
fmt: ## gofmt the tree (check-only)
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: test
test: ## run tests (device read excluded — no nsm tag)
	go test ./...

.PHONY: build
build: ## build the nitro CLI
	go build $(GOFLAGS) -ldflags="-s -w -X main.version=$(VERSION)" -o bin/nitro ./cmd/nitro

.PHONY: build-nsm
build-nsm: ## compile-check the /dev/nsm device Source (enclave-only; never run here)
	GOOS=linux go build -tags nsm ./...

.PHONY: vuln
vuln: ## govulncheck
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: clean
clean: ## remove build artifacts
	rm -rf bin/ dist/
