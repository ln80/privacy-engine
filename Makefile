.PHONY: lint security fuzz test test/cov_html test/cov_total bench bench/profile doc

GOVULNCHECK_VERSION := v1.10.0
FUZZTIME ?= 30s

lint:
	golangci-lint run --enable misspell

security:
	gosec ./...
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# fuzz runs every fuzz target for FUZZTIME each: make fuzz FUZZTIME=2m
fuzz:
	@set -e; for pkg in . ./aes; do \
		for target in $$(go test -list '^Fuzz' $$pkg | grep '^Fuzz'); do \
			echo "== $$pkg $$target"; \
			go test -run='^$$' -fuzz="^$$target$$" -fuzztime=$(FUZZTIME) $$pkg; \
		done; \
	done

test:
	packages=$$(go list ./... | grep -v privacytest); \
	go test -race -cover $$packages -coverprofile coverage.out -covermode atomic

test/cov_html:
	go tool cover -html=coverage.out

test/cov_total:
	go tool cover -func=coverage.out | grep total

bench:
	go test -bench=$(b) -benchmem -memprofile mem.prof -memprofilerate=1  -run=^$$ -v

bench/profile:
	go tool pprof -alloc_objects mem.prof

doc:
	godoc -http=:6060
