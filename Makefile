PKG:=github.com/kayrus/gof5
APP_NAME:=gof5
PWD:=$(shell pwd)
UID:=$(shell id -u)
VERSION:=$(shell git describe --tags --always --dirty="-dev")
GOOS:=$(shell go env GOOS)
LDFLAGS:=-X main.Version=$(VERSION) -w -s
GOOS:=$(strip $(shell go env GOOS))

ifeq "$(GOOS)" "windows"
SUFFIX=.exe
endif

ifeq "$(GOOS)" "freebsd"
# customized vendor dir with a patch
$(shell go mod vendor)
$(shell patch -si freebsd.patch)
endif

# CGO must be enabled
export CGO_ENABLED:=1

build: fmt vet
	go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)_$(GOOS)$(SUFFIX) ./cmd/gof5

docker:
	docker run -ti --rm -e GOCACHE=/tmp -v $(PWD):/$(APP_NAME) -u $(UID):$(UID) --workdir /$(APP_NAME) golang:latest make

fmt:
	gofmt -s -w cmd pkg

vet:
	go vet -mod=vendor ./...

static:
	staticcheck ./cmd/... ./pkg/...

mod:
	go mod vendor

test:
	go test -v ./cmd/... ./pkg/...
