.PHONY: lint security test test/cov_html test/cov_total bench bench/profile doc

lint:
	golangci-lint run --enable misspell

security:
	gosec -exclude-dir=privacytest ./...

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
