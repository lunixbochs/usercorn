usercorn
----

[![Build Status](https://travis-ci.org/lunixbochs/usercorn.svg?branch=master)](https://travis-ci.org/lunixbochs/usercorn)

Building
---

- You need [Unicorn](http://www.unicorn-engine.org/) and [Capstone](http://www.capstone-engine.org/) installed to use this.
- The latest stable version of Go is recommended for performance and compatibility reasons.
- Make sure you have the GOPATH environment variable pointed at a directory like `$HOME/go`, and `$GOPATH/bin` is in your PATH.

Simply `go get -u github.com/lunixbochs/usercorn/go/usercorn`.

To do a source tree build, you can also run `make` or `go build -i -o usercorn ./go/usercorn`

Examples
---

    ./usercorn bins/x86.linux.elf
    ./usercorn bins/x86_64.linux.elf
    ./usercorn bins/x86.darwin.macho
    ./usercorn bins/x86_64.darwin.macho
    ./usercorn bins/x86.linux.cgc
    ./usercorn bins/mipsel.linux.elf

What.
----

- User-space system emulator.
- Backed by [Unicorn](http://www.unicorn-engine.org/).
- Similar to qemu-user.
- Unlike qemu-user, __does not require the same OS for which the binary was built__.
- Wait, __what?__ What does that mean?
- Syscalls are coerced into the Go language APIs using persuasive fit techniques. Syscalls s/should/might/ work almost anywhere the language does.
- This means Usercorn should work anywhere Unicorn and Go work.

Why?
----

- Debug stubborn binaries. I had a binary gdb refused to debug ("Program exited during startup."). No problem. Usercorn can single-step into the program for you.
- Debug foreign architecture and OS binaries. You don't need a MIPS box. You don't need qemu-user. You don't even need Linux.
- Write tools, like fuzzers, static analyzers, recompilers, memory and register tracing...
- Selectively call functions from within a binary.
- Whatever you want. Open an issue if you have a cool debugging / reverse engineering idea I didn't think about - I may just implement it.

Caveats
----

- Your userspace might be incredibly confusing to the target binary.
- No API for memory mapped files yet (kinda, if mmap() currently gets a file descriptor argument it will manually copy the file into memory).

[See Also](https://xkcd.com/1406/)
----
![Universal converter](https://imgs.xkcd.com/comics/universal_converter_box.png)
