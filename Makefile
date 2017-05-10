.PHONY: get test deps usercorn imgtrace shellcode repl fuzz cfg trace
.DEFAULT_GOAL := build

build: get all

# dependency targets
DEST = $(shell mkdir -p deps/build; cd deps && pwd)
FIXRPATH := touch
LIBEXT := so
OS := $(shell uname -s)
ARCH := $(shell uname -m)

ifeq "$(OS)" "Darwin"
	LIBEXT = dylib
	FIXRPATH = install_name_tool \
		-add_rpath @executable_path/lib \
		-add_rpath @executable_path/deps/lib \
		-change libunicorn.1.dylib @rpath/libunicorn.1.dylib \
		-change libcapstone.dylib @rpath/libcapstone.dylib \
		-change libkeystone.0.dylib @rpath/libkeystone.0.dylib
endif

# figure out if we can download Go
GOVERSION=1.8.1
ifeq "$(ARCH)" "x86_64"
	ifeq "$(OS)" "Darwin"
		GOURL = "https://storage.googleapis.com/golang/go$(GOVERSION).darwin-amd64.tar.gz"
	else ifeq "$(OS)" "Linux"
		GOURL = "https://storage.googleapis.com/golang/go$(GOVERSION).linux-amd64.tar.gz"
	endif
endif
ifeq "$(ARCH)" "i686"
	ifeq "$(OS)" "Linux"
		GOURL = "https://storage.googleapis.com/golang/go$(GOVERSION).linux-386.tar.gz"
	endif
endif
ifneq (,$(filter $(ARCH),armv6l armv7l armv8l))
	ifeq "$(OS)" "Linux"
		GOURL = "https://storage.googleapis.com/golang/go$(GOVERSION).linux-armv6l.tar.gz"
	endif
endif

ifeq ($(GOURL),)
	GOMSG = "Go 1.5 or later is required. Visit https://golang.org/dl/ to download."
else
	GODIR = go-$(ARCH)-$(OS)
endif

deps/$(GODIR):
	echo $(GOMSG)
	[ -n $(GOURL) ] && \
	mkdir -p deps/build deps/gopath && \
	cd deps/build && \
	curl -o go-dist.tar.gz "$(GOURL)" && \
	cd .. && tar -xf build/go-dist.tar.gz && \
	mv go $(GODIR)

deps/lib/libunicorn.1.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/unicorn-engine/unicorn.git && git --git-dir unicorn fetch; \
	cd unicorn && git clean -fdx && git reset --hard origin/master && \
	make && make PREFIX=$(DEST) install

deps/lib/libcapstone.3.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/aquynh/capstone.git && git --git-dir capstone pull; \
	cd capstone && git clean -fdx && git reset --hard origin/master; \
	mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=$(DEST) -DCMAKE_BUILD_TYPE=RELEASE .. && \
	make -j2 PREFIX=$(DEST) install

deps/lib/libkeystone.0.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/keystone-engine/keystone.git && git --git-dir keystone pull; \
	cd keystone; git clean -fdx && git reset --hard origin/master; mkdir build && cd build && \
	cmake -DCMAKE_INSTALL_PREFIX=$(DEST) -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" .. && \
	make -j2 install

deps: deps/lib/libunicorn.1.$(LIBEXT) deps/lib/libcapstone.3.$(LIBEXT) deps/lib/libkeystone.0.$(LIBEXT) deps/$(GODIR)

# Go executable targets
.gopath:
	mkdir -p .gopath/src/github.com/lunixbochs
	ln -s ../../../.. .gopath/src/github.com/lunixbochs/usercorn

LD_LIBRARY_PATH=
DYLD_LIBRARY_PATH=
ifneq "$(OS)" "Darwin"
	LD_LIBRARY_PATH := "$(LD_LIBRARY_PATH):$(DEST)/lib"
else
	DYLD_LIBRARY_PATH := "$(DYLD_LIBRARY_PATH):$(DEST)/lib"
endif
GOBUILD := go build -i
PATHX := '$(DEST)/$(GODIR)/bin:$(PATH)'
export CGO_CFLAGS = -I$(DEST)/include
export CGO_LDFLAGS = -L$(DEST)/lib

ifneq ($(wildcard $(DEST)/$(GODIR)/.),)
	export GOROOT := $(DEST)/$(GODIR)
endif
ifneq ($(GOPATH),)
	export GOPATH := $(GOPATH):$(shell pwd)/.gopath
else
	export GOPATH := $(DEST)/gopath:$(shell pwd)/.gopath
endif
DEPS=$(shell env PATH=$(PATHX) GOROOT=$(GOROOT) GOPATH=$(GOPATH) go list -f '{{join .Deps "\n"}}' ./go/... | grep -v usercorn | grep '\.' | sort -u)

usercorn: .gopath
	sh -c "PATH=$(PATHX) $(GOBUILD) -o usercorn ./go/cmd/usercorn"
	$(FIXRPATH) usercorn

imgtrace: .gopath
	sh -c "PATH=$(PATHX) $(GOBUILD) -o imgtrace ./go/cmd/imgtrace"
	$(FIXRPATH) imgtrace

shellcode: .gopath
	sh -c "PATH=$(PATHX) $(GOBUILD) -o shellcode ./go/cmd/shellcode"
	$(FIXRPATH) shellcode

repl: .gopath
	sh -c "PATH=$(PATHX) $(GOBUILD) -o repl ./go/cmd/repl"
	$(FIXRPATH) repl

fuzz: .gopath
	sh -c "PATH=$(PATHX) $(GOBUILD) -o fuzz ./go/cmd/fuzz"
	$(FIXRPATH) fuzz

cfg: .gopath
	sh -c "PATH=$(PATHX) $(GOBUILD) -o cfg ./go/cmd/cfg"
	$(FIXRPATH) cfg

cgc: .gopath
	sh -c "PATH=$(PATHX) $(GOBUILD) -o cgc ./go/cmd/cgc"
	$(FIXRPATH) cgc

trace: .gopath
	sh -c "PATH=$(PATHX) $(GOBUILD) -o trace ./go/cmd/trace"
	$(FIXRPATH) trace

get: .gopath
	sh -c "PATH=$(PATHX) go get -u ${DEPS}"

test: .gopath
	sh -c "LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) DYLD_LIBRARY_PATH=$(DYLD_LIBRARY_PATH) PATH=$(PATHX) go test -v ./go/..."

bench: .gopath
	sh -c "LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) DYLD_LIBRARY_PATH=$(DYLD_LIBRARY_PATH) PATH=$(PATHX) go test -v -benchmem -bench=. ./go/..."

all: usercorn imgtrace shellcode repl fuzz cgc
