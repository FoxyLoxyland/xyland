# xyland — target lokal yang sama dengan CI
GO ?= go
export GOTOOLCHAIN := local
export CGO_ENABLED := 0

.PHONY: build test vet fmt check ci
build:
	$(GO) build -o xyland ./cmd/xyland

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal

check:
	@test -z "$$(gofmt -l cmd internal)" || (echo "belum terformat:"; gofmt -l cmd internal; exit 1)

ci: check vet test build
