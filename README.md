usercorn
----

[![Build Status](https://travis-ci.org/lunixbochs/usercorn.svg?branch=master)](https://travis-ci.org/lunixbochs/usercorn)

Dependencies
---

- Latest master build of [Unicorn](http://www.unicorn-engine.org/). Both Usercorn and Unicorn are rapidly changing, so make sure both are completely up-to-date before submitting a bug report.
- Latest master build of [Keystone](http://www.keystone-engine.org/).
- Stable version of [Capstone](http://www.capstone-engine.org/)
- Go 1.5 or newer
- Make sure you have the GOPATH environment variable pointed at a directory like `$HOME/go`, and `$GOPATH/bin` is in your PATH

Building
---

From the source tree, run `make`. There are several bonus targets, which can be built with `make usercorn imgtrace shellcode repl`.

Examples
---

    usercorn bins/x86.linux.elf
    usercorn bins/x86_64.linux.elf
    usercorn bins/x86.darwin.macho
    usercorn bins/x86_64.darwin.macho
    usercorn bins/x86.linux.cgc
    usercorn bins/mipsel.linux.elf

What.
----

- Userspace and kernel emulator.
- Backed by [Unicorn](http://www.unicorn-engine.org/).
- Similar to qemu-user.
- Unlike qemu-user, __does not require the same OS for which the binary was built__.
- Usercorn has an abstract kernel interface making it very easy to build kernel and syscall emulation.

Usercorn could be used to emulate 32-bit and 64-bit arm/mips/x86/sparc binaries on linux, darwin, bsd, DECREE, and even toy OSes like Redux.

Right now, x86\_64 linux and DECREE are the best supported guests.

Why?
----

- Usercorn aims to be a framework to simplify emulating and deeply hooking a userspace environment for many target architectures and kernel ABIs.
- I regularly build new tools on top of Usercorn, which can be found in the cmd/ directory. I'm also always willing to talk about it in great depth if you want to track me down on [Twitter](https://twitter.com/lunixbochs).
- Seriously go look at the [tool source](https://github.com/lunixbochs/usercorn/tree/master/go/cmd). It's really easy to build interesting tools on top of Usercorn, so go make my day by submitting a PR out of the blue or asking questions.
- Debug stubborn binaries. I had a binary gdb refused to debug ("Program exited during startup."). No problem. Usercorn can single-step into the program for you.
- Debug foreign architecture and OS binaries. You don't need a MIPS box. You don't need qemu-user. You don't even need Linux.
- Write tools, like fuzzers, static analyzers, recompilers, memory and register tracing...
- Selectively call functions from within a binary.
- Whatever you want. Open an issue if you have a cool debugging / reverse engineering idea I didn't think about - I may just implement it.

Caveats
----

- Your userspace might be incredibly confusing to the target binary.
- No API for memory mapped files yet (kinda, if mmap() currently gets a file descriptor argument it will manually copy the file into memory).
- I only have maybe 20% of the posix syscalls implemented, which is enough to run basic binaries. Busybox works great. Dynamically linked stuff not so much. I keep breaking this, and I probably need to rework the TLS and x86 segment stuff again.

[See Also](https://xkcd.com/1406/)
----
![Universal converter](https://imgs.xkcd.com/comics/universal_converter_box.png)
