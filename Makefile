.PHONY: go get test
.DEFAULT_GOAL := go

go:
	go build -i -o usercorn ./go/usercorn

get:
	go get ./go

test:
	go test -v ./go/...
