PKG:=github.com/kayrus/gof5
APP_NAME:=gof5
PWD:=$(shell pwd)
UID:=$(shell id -u)
VERSION:=$(shell git describe --tags --always --dirty="-dev")
LDFLAGS:=-X main.Version=$(VERSION)

# CGO is incompatible with AD/LDAP
#export CGO_ENABLED:=0

build: fmt vet
	GOOS=linux go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME) ./cmd
	GOOS=freebsd go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)_freebsd ./cmd
	GOOS=darwin go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME)_darwin ./cmd
	#GOOS=windows go build -mod=vendor -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME).exe ./cmd

docker:
	docker run -ti --rm -e GOCACHE=/tmp -v $(PWD):/$(APP_NAME) -u $(UID):$(UID) --workdir /$(APP_NAME) golang:latest make

fmt:
	gofmt -s -w cmd pkg

vet:
	go vet -mod=vendor ./cmd ./pkg

mod:
	go mod vendor

test:
	go test -v ./pkg
