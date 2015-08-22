usercorn
----

*Instructions*

You need [Unicorn](http://www.unicorn-engine.org/) installed, including the Python bindings (`cd bindings/python; make install`)

    pip install -r requirements.txt
    python run.py tests/test.elf
    # (note: MachO loading is implemented but the binary crashes at some point in my tests)
    python run.py tests/test.macho

What.
----

- User-space system emulator.
- Backed by [Unicorn](http://www.unicorn-engine.org/).
- Similar to qemu-user.
- Unlike qemu-user, __does not require the same OS for which the binary was built__.
- Wait, __what?__ What does that mean?
- Syscalls are coerced into the Python API using persuasive fit techniques. Syscalls s/should/might/ work almost anywhere Python does.
- Hence, Usercorn should work anywhere Unicorn and Python do.

Caveats
----

- Your userspace might be incredibly confusing to the target binary.
- No API for memory mapped files yet.

[See Also](https://xkcd.com/1406/)
----
![Universal converter](https://imgs.xkcd.com/comics/universal_converter_box.png)
