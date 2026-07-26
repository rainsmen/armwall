VERSION ?= dev
GO ?= go
LDFLAGS = -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o armwall .

test:
	$(GO) test ./...
	node --check web/app.js
	sh -n gateway.sh install.sh one-click-install.sh update-core.sh naive-supervisor.sh

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o armwall-linux-armv6 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o armwall-linux-armv7 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o armwall-linux-arm64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o armwall-linux-amd64 .

.PHONY: build test release
