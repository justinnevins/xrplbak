VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  = -s -w -buildid= -X main.version=$(VERSION) -X github.com/justinnevins/xrplbak/internal/backup.ToolVersion=xrplbak/$(VERSION)
GOFLAGS  = -trimpath

.PHONY: build test lint clean checksums

build:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/xrplbak-linux-amd64  ./cmd/xrplbak
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/xrplbak-darwin-arm64 ./cmd/xrplbak

checksums: build
	cd bin && sha256sum xrplbak-* > SHA256SUMS && cat SHA256SUMS

test:
	go test ./...

lint:
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"
	go vet ./...

clean:
	rm -rf bin
