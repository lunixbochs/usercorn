.PHONY: usercorn get test
.DEFAULT_GOAL := build

DEPS=$(shell go list -f '{{join .Deps "\n"}}' ./go/... | grep -v usercorn | grep '\.' | sort -u)

build: get usercorn

usercorn:
	go build -i -o usercorn ./go/usercorn

get:
	go get -u ${DEPS}

test:
	go test -v ./go/...
