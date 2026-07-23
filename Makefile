VERSION ?= dev
build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o armwall .
release:
	GOOS=linux GOARCH=arm GOARM=6 go build -trimpath -ldflags "-s -w" -o armwall-linux-armv6 .
	GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags "-s -w" -o armwall-linux-armv7 .
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o armwall-linux-arm64 .
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o armwall-linux-amd64 .
