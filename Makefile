PKG:=github.com/kayrus/gof5
APP_NAME:=gof5
PWD:=$(shell pwd)
UID:=$(shell id -u)
VERSION:=$(shell git describe --tags --always --dirty="-dev")
GOOS:=$(shell go env GOOS)
LDFLAGS:=-X main.Version=$(VERSION) -w -s
GOOS:=$(strip $(shell go env GOOS))
GOARCHs:=$(strip $(shell go env GOARCH))

ifeq "$(GOOS)" "windows"
SUFFIX=.exe
endif

ifeq "$(GOOS)" "darwin"
GOARCHs=amd64 arm64
endif

# CGO must be enabled
export CGO_ENABLED:=1

build: fmt vet
	$(foreach GOARCH,$(GOARCHs),$(shell GOARCH=$(GOARCH) go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)_$(GOOS)_$(GOARCH)$(SUFFIX) ./cmd/gof5))

docker:
	docker run -ti --rm -e GOCACHE=/tmp -v $(PWD):/$(APP_NAME) -u $(UID):$(UID) --workdir /$(APP_NAME) golang:1.16 make

fmt:
	gofmt -s -w cmd pkg

vet:
	go vet -mod=vendor ./cmd/... ./pkg/...

static:
	staticcheck ./cmd/... ./pkg/...

mod:
	go mod vendor

test:
	go test -v ./cmd/... ./pkg/...
