usercorn
----

You need [Unicorn](http://www.unicorn-engine.org/) installed to use this.

Usercorn has two implementations: Go and Python. The Go variant is more advanced, faster (+10x), and more stable, but harder to script.

*Go Instructions*

    # preconditions:
    # make sure you are using go1.5
    # you will also need capstone development headers

    # not windows:
    make

    # windows:
    go build -i -o usercorn ./go

    # test executables
    ./usercorn bins/x86.linux.elf
    ./usercorn bins/x86_64.linux.elf
    ./usercorn bins/x86.darwin.macho
    ./usercorn bins/x86_64.darwin.macho
    ./usercorn bins/x86.linux.cgc
    ./usercorn bins/mipsel.linux.elf

*Python Instructions (DEPRECATED)*

(*The Python frontend has been deprecated and will eventually be replaced with a native module*)

Install the Unicorn Python bindings (`cd bindings/python; make install`)

    pip install -r py/requirements.txt

    # test executables
    python py/run.py bins/x86.linux.elf
    python py/run.py bins/x86_64.linux.elf
    python py/run.py bins/x86.darwin.macho
    python py/run.py bins/x86_64.darwin.macho
    python py/run.py bins/x86.linux.cgc

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
