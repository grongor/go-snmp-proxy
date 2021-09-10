GO_ACC ?= go-acc
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
	go test --timeout 5m $(GO_TEST_FLAGS) ./...
	go test --timeout 5m $(GO_TEST_FLAGS) --race ./...
	go test --timeout 5m $(GO_TEST_FLAGS) --count 100 ./...

.PHONY: coverage
coverage:
	$(GO_ACC) --covermode set --output coverage.cov --ignore ./snmpproxy/mib ./...
	$(GO_ACC) --covermode set --output coverage-netsnmp.cov ./snmpproxy/mib
	$(GO_ACC) --covermode set --output coverage-nonetsnmp.cov ./snmpproxy/mib -- -tags=nonetsnmp
	cat coverage-netsnmp.cov coverage-nonetsnmp.cov | grep -v 'mode: ' >> coverage.cov
	rm coverage-netsnmp.cov coverage-nonetsnmp.cov

.PHONY: clean
clean:
	rm -rf bin
	rm -rf dist

$(BIN)/golangci-lint:
	curl --retry 5 -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh
