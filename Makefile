PKG:=github.com/kayrus/gof5
APP_NAME:=gof5
PWD:=$(shell pwd)
UID:=$(shell id -u)
VERSION:=$(shell git describe --tags --always --dirty="-dev")
LDFLAGS:=-X $(PKG)/pkg.Version=$(VERSION)

export CGO_ENABLED:=0

build: fmt vet
	GOOS=linux go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME) ./cmd
	#GOOS=darwin go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)_darwin ./cmd
	#GOOS=windows go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME).exe ./cmd

docker:
	docker run -ti --rm -e GOCACHE=/tmp -v $(PWD):/$(APP_NAME) -u $(UID):$(UID) --workdir /$(APP_NAME) golang:latest make

fmt:
	gofmt -s -w cmd pkg

vet:
	go vet -mod=vendor ./cmd ./pkg
