.PHONY: usercorn get test
.DEFAULT_GOAL := build

DEPS=$(shell go list -f '{{join .Deps "\n"}}' ./go/... | grep -v usercorn | xargs go list -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs)

build: get usercorn

usercorn:
	go build -i -o usercorn ./go/usercorn

get:
	go get -u ${DEPS}

test:
	go test -v ./go/...
