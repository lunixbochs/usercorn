usercorn
----

You need [Unicorn](http://www.unicorn-engine.org/) installed to use this. It is currently in private beta, so stay tuned.

*Python Instructions*

Install the Unicorn Python bindings (`cd bindings/python; make install`)

    pip install -r py/requirements.txt
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
- Syscalls are coerced into the Python language APIs using persuasive fit techniques. Syscalls s/should/might/ work almost anywhere the language does.
- Hence, Usercorn should work anywhere Unicorn and Python do.

Caveats
----

- Your userspace might be incredibly confusing to the target binary.
- No API for memory mapped files yet.

[See Also](https://xkcd.com/1406/)
----
![Universal converter](https://imgs.xkcd.com/comics/universal_converter_box.png)
