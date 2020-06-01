export BIN = ${PWD}/bin
export GOBIN = $(BIN)

.PHONY: build
build:
	for CMD in `ls cmd`; do \
		go build ./cmd/$$CMD; \
	done

.PHONY: check
check: lint test

.PHONY: lint
lint: $(BIN)/golangci-lint
	$(BIN)/golangci-lint run

.PHONY: fix
fix: $(BIN)/golangci-lint
	$(BIN)/golangci-lint run --fix

.PHONY: test
test:
	timeout 300 go test ./...
	timeout 300 go test --race ./...
	timeout 300 go test --count 100 ./...

.PHONY: clean
clean:
	rm -rf bin

$(BIN)/golangci-lint:
	curl --retry 5 -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s v1.27.0
