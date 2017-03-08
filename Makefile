.PHONY: get test deps usercorn imgtrace shellcode repl
.DEFAULT_GOAL := build

build: get usercorn

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
		-change libcapstone.3.dylib @rpath/libcapstone.3.dylib
endif

# figure out if we can download Go
ifeq "$(ARCH)" "x86_64"
	ifeq "$(OS)" "Darwin"
		GOURL = https://storage.googleapis.com/golang/go1.6.2.darwin-amd64.tar.gz
	else ifeq "$(OS)" "Linux"
		GOURL = https://storage.googleapis.com/golang/go1.6.2.linux-amd64.tar.gz
	endif
endif
ifeq "$(ARCH)" "i686"
	ifeq "$(OS)" "Linux"
		GOURL = https://storage.googleapis.com/golang/go1.6.2.linux-386.tar.gz
	endif
endif
ifneq (,$(filter $(ARCH),armv6l armv7l armv8l))
	ifeq "$(OS)" "Linux"
		GOURL = https://storage.googleapis.com/golang/go1.6.2.linux-armv6l.tar.gz
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
	sed -e "/samples/d" -i. Makefile && \
	make -j2 && make PREFIX=$(DEST) install

deps/lib/libcapstone.3.$(LIBEXT):
	cd deps/build && \
	git clone https://github.com/aquynh/capstone.git && git --git-dir capstone pull; \
	cd capstone && git clean -fdx && git reset --hard origin/master && \
	sed -e "/cd tests/d" -i. Makefile && \
	make -j2 && make PREFIX=$(DEST) install

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
	GO_LDF = -ldflags '-extldflags -Wl,-rpath=$$ORIGIN/deps/lib:$$ORIGIN/lib'
	LD_LIBRARY_PATH := "$(LD_LIBRARY_PATH):$(DEST)/lib"
else
	DYLD_LIBRARY_PATH := "$(DYLD_LIBRARY_PATH):$(DEST)/lib"
endif
GOBUILD := go build -i $(GO_LDF)
export CGO_CFLAGS = -I$(DEST)/include
export CGO_LDFLAGS = -L$(DEST)/lib
PATHX := "$(DEST)/$(GODIR)/bin:$(PATH)"

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

get: .gopath
	sh -c "PATH=$(PATHX) go get $(GO_LDF) -u ${DEPS}"

test: .gopath
	sh -c "LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) DYLD_LIBRARY_PATH=$(DYLD_LIBRARY_PATH) PATH=$(PATHX) go test $(GO_LDF) -v ./go/..."

all: usercorn imgtrace shellcode repl
