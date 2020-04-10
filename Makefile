
.PHONY: all
all: fmt build

.PHONY: release
release: fmt release_wol_server

.PHONY: build
build: wol_server

.PHONY: fmt
fmt:
	@go fmt ./...

.PHONY: wol_server
wol_server:
	@go build -ldflags "-w -s" -o bin/wol_server

.PHONY: release_wol_server
release_wol_server: wol_server
ifneq ($(UPX_PATH),)
	$(UPX_PATH) -9 bin/wol_server
endif

.PHONY: clean
clean:
	@rm -rf bin
	@go clean

.PHONY: distclean
distclean:
	@rm -rf bin
	@go clean --modcache
