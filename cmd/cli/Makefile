# build: static Linux binary, built ON a Linux host (uses the host's gcc). Unchanged; this is the
# original target and still what you run on the scan box itself.
build:
	CGO_ENABLED=1 GOOS=linux go build -a -ldflags '-linkmode external -extldflags "-static"' -o mykmyk

# build-linux: cross-compile a static linux/amd64 binary FROM macOS (or any host) for the amd64
# test box. mykmyk needs CGO (go-sqlite3, grdp), so a C cross-compiler targeting linux/amd64 is
# required - install it once with:
#     brew install FiloSottile/musl-cross/musl-cross
# GOARCH is pinned to amd64 so an arm64 Mac does not accidentally emit an arm64 binary.
build-linux:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-linux-musl-gcc \
		go build -ldflags '-linkmode external -extldflags "-static"' -o mykmyk

# build-native: quick, non-static build for the machine you are on (e.g. testing on the Mac).
# Not deployable to the Linux box - just for local iteration.
build-native:
	go build -o mykmyk

.PHONY: build build-linux build-native
