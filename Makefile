.PHONY: get test usercorn imgtrace
.DEFAULT_GOAL := build

DEPS=$(shell go list -f '{{join .Deps "\n"}}' ./go/... | grep -v usercorn | grep '\.' | sort -u)

build: get usercorn

export GOPATH := $(GOPATH):$(shell pwd)/.gopath
.gopath:
	mkdir -p .gopath/src/github.com/lunixbochs
	ln -s ../../../.. .gopath/src/github.com/lunixbochs/usercorn

usercorn: .gopath
	go build -i -o usercorn ./go/cmd/usercorn

imgtrace: .gopath
	go build -i -o imgtrace ./go/cmd/imgtrace

get:
	go get -u ${DEPS}

test:
	go test -v ./go/...
