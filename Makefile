
.PHONY: all
all: fmt build

.PHONY: build
build: wol_server

.PHONY: fmt
fmt:
	@go fmt ./...

.PHONY: wol_server
wol_server:
	@go build -ldflags "-w -s" -o bin/wol_server

.PHONY: clean
clean:
	@rm -rf bin

.PHONY: distclean
distclean:
	@rm -rf bin
	@go clean --modcache
