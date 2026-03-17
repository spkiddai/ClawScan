VERSION ?= 0.1.0
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)"
BINARY  := clawscan
BUILD_DIR := build
CMD := ./cmd/clawscan/

.PHONY: build build-all test clean release

build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) $(CMD)

build-all:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64         $(CMD)
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-arm64         $(CMD)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64        $(CMD)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-arm64        $(CMD)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe   $(CMD)
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-arm64.exe   $(CMD)
	@echo ""
	@echo "构建完成:"
	@ls -lh $(BUILD_DIR)/

test:
	go test ./...

clean:
	rm -f $(BINARY)
	rm -rf $(BUILD_DIR)

release:
	./scripts/release.sh v$(VERSION)
