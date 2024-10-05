# DOCKER_NETWORK = lambda-local

# DYNAMODB_PORT  = 8070
# DYNAMODB_VOLUME = dynamodb-local-v2.0

# KMS_PORT  = 8090

# export DYNAMODB_ENDPOINT = http://localhost:$(DYNAMODB_PORT)
# export KMS_ENDPOINT = http://localhost:$(KMS_PORT)

.PHONY: lint
lint:
	golangci-lint run --enable misspell

test:
	packages=`go list ./... | grep -v privacytest`; \
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