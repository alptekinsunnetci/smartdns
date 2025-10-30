APP=smart-dns
PKG=./...

.PHONY: build test run tidy

build:
	go build -trimpath -ldflags "-s -w" -o bin/$(APP) ./cmd/smart-dns

test:
	go test -race -count=1 $(PKG)

run:
	go run ./cmd/smart-dns

tidy:
	go mod tidy


