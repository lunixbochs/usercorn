.PHONY: get test deps usercorn imgtrace shellcode repl
.DEFAULT_GOAL := build

DEPS=$(shell go list -f '{{join .Deps "\n"}}' ./go/... | grep -v usercorn | grep '\.' | sort -u)

build: get usercorn

# dependency targets
FIXRPATH := touch
LIBEXT := so
OS := $(shell uname -s)

ifeq "$(OS)" "Darwin"
	LIBEXT = dylib
	FIXRPATH = install_name_tool \
		-add_rpath @executable_path/lib \
		-add_rpath @executable_path/deps/lib \
		-change libunicorn.1.dylib @rpath/libunicorn.1.dylib \
		-change libcapstone.3.dylib @rpath/libcapstone.3.dylib
endif

DEST = $(shell mkdir -p deps/build; cd deps && pwd)

deps/libunicorn.1.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/unicorn-engine/unicorn.git && git --git-dir unicorn pull; \
	cd unicorn && git reset --hard && \
	sed -e '/samples/d' -i. Makefile && \
	make -j2 PREFIX=$(DEST) install

deps/libcapstone.3.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/aquynh/capstone.git && git --git-dir capstone pull; \
	cd capstone && git reset --hard && \
	sed -e '/cd tests/d' -i. Makefile && \
	make -j2 PREFIX=$(DEST) install

deps/libkeystone.0.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/keystone-engine/keystone.git && git --git-dir keystone pull; mkdir -p keystone/build; \
	cd keystone/build && \
	cmake -DCMAKE_INSTALL_PREFIX=$(DEST) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" .. && \
	make -j2 install

deps: deps/libunicorn.1.$(LIBEXT) deps/libcapstone.3.$(LIBEXT) deps/libkeystone.0.$(LIBEXT)

# Go targets
export GOPATH := $(GOPATH):$(shell pwd)/.gopath
.gopath:
	mkdir -p .gopath/src/github.com/lunixbochs
	ln -s ../../../.. .gopath/src/github.com/lunixbochs/usercorn

GOBUILD := go build -i -ldflags '-extldflags -L$(DEST)/lib'

usercorn: .gopath
	$(GOBUILD) -o usercorn ./go/cmd/usercorn
	$(FIXRPATH) usercorn

imgtrace: .gopath
	$(GOBUILD) -o imgtrace ./go/cmd/imgtrace
	$(FIXRPATH) imgtrace

shellcode: .gopath
	$(GOBUILD) -o shellcode ./go/cmd/shellcode
	$(FIXRPATH) shellcode

repl: .gopath
	$(GOBUILD) -o repl ./go/cmd/repl
	$(FIXRPATH) repl

get:
	go get -u ${DEPS}

test:
	go test -v ./go/...

all: usercorn imgtrace shellcode repl
