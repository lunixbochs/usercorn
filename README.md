usercorn
----

[![Build Status](https://travis-ci.org/lunixbochs/usercorn.svg?branch=master)](https://travis-ci.org/lunixbochs/usercorn)
[![GoDoc](https://godoc.org/github.com/lunixbochs/usercorn?status.svg)](https://godoc.org/github.com/lunixbochs/usercorn)
[![Slack](https://lunixbochs.herokuapp.com/badge.svg)](https://lunixbochs.herokuapp.com/)

Building
---

Usercorn depends on Go 1.6 or newer, as well as the latest unstable versions of Capstone, Unicorn, and Keystone.

`make deps` will attempt to install all of the above into the source tree (requires `cmake`).

`make` will update Go packages and build `usercorn`

Additional binaries such as `repl`, `imgtrace`, and `shellcode` can be built with `make all`

Example Commands
---

    usercorn bins/x86.linux.elf
    usercorn bins/x86_64.linux.elf
    usercorn bins/x86.darwin.macho
    usercorn bins/x86_64.darwin.macho
    usercorn bins/x86.linux.cgc
    usercorn bins/mipsel.linux.elf

    usercorn -trace bins/x86.linux.elf
    usercorn -trace -to trace.uc bins/x86.linux.elf
    trace -pretty trace.uc
    usercorn -repl bins/x86.linux.elf

What.
----

- Usercorn is an analysis and emulator framework, with a base similar to qemu-user.
- It can run arbitrary binaries on a different host kernel, unlike qemu-user.
- While recording full system state at every instruction.
- to a serializable compact format capable of rewind and re-execution.
- It's useful out of the box for debugging and dynamic analysis.
- With an arch-neutral powerful lua-based scripting language and debugger.
- It's also easy to extend and use to build your own tools.

Usercorn could be used to emulate 16-bit DOS, 32-bit and 64-bit ARM/MIPS/x86/SPARC binaries for Linux, Darwin, BSD, DECREE, and even operating systems like Redux.

Right now, x86\_64 linux and DECREE are the best supported guests.

Why?
----

- Usercorn aims to be a framework to simplify emulating and deeply hooking a userspace environment for many target architectures and kernel ABIs.
- Debug stubborn binaries. I had a binary gdb refused to debug ("Program exited during startup."). No problem. Usercorn can single-step into the program for you.
- Debug foreign architecture and OS binaries. You don't need a MIPS box. You don't need qemu-user. You don't even need Linux.
- Write tools, like fuzzers, static analyzers, recompilers, memory and register analysis, overlay code coverage and machine state into IDA/Binary Ninja.
- Selectively call functions from within a binary. Usercorn will map a binary and emulate the kernel for you.
- Whatever you want. Open an issue if you have a cool debugging / reverse engineering idea I didn't think about - I may just implement it.

Caveats
----

- Your userspace might be incredibly confusing to the target binary.
- No API for memory mapped files yet (kinda, if mmap() currently gets a file descriptor argument it will manually copy the file into memory).
- I only have maybe 20% of the posix syscalls implemented, which is enough to run basic binaries. Busybox works great.

[See Also](https://xkcd.com/1406/) (credit: XKCD)
----
![Universal converter](https://imgs.xkcd.com/comics/universal_converter_box.png)
