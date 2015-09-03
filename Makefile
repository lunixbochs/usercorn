.PHONY: go test
.DEFAULT_GOAL := go

go:
	go build -i -o usercorn ./go

test:
	go test ./go/...
