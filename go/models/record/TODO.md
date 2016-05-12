TODO
----

[ ] Signal issue
[ ] Special (non-integer) register types
[ ] Unicorn CPU mode changed (like ARM -> Thumb) - detect this with T bit set in CPSR or a jump to something with low bit set
    can also do this (even for computed jumps via BX and BLX) by looking at register value when jump happened
