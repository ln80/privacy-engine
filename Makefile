DOCKER_NETWORK = lambda-local

DYNAMODB_PORT  = 8070
DYNAMODB_VOLUME = dynamodb-local-v2.0

KMS_PORT  = 8090

export DYNAMODB_ENDPOINT = http://localhost:$(DYNAMODB_PORT)
export KMS_ENDPOINT = http://localhost:$(KMS_PORT)

.PHONY: lint
lint:
	golangci-lint run --enable misspell

ci/test: 
	go test -race -cover ./... -coverprofile coverage.out -covermode atomic

test: lint ci/test

test/coverage:
	go tool cover -html=coverage.out

bench:
	go test -bench=$(b) -benchmem -memprofile mem.prof -memprofilerate=1  -run=^$$ -v

bench/profile:
	go tool pprof -alloc_objects mem.prof