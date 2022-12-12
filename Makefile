GOLANGCI_LINT ?= go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest
GO_ACC ?= go run github.com/golangci/golangci-lint/cmd/golangci-lint@latest
GO_ACC ?= go run github.com/ory/go-acc@latest

.PHONY: build
build:
	go build ./cmd/...

.PHONY: check
check: lint test

.PHONY: lint
lint:
	$(GOLANGCI_LINT) run

.PHONY: fix
fix:
	$(GOLANGCI_LINT) run --fix

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
