Usercorn Trace Format
====

The disk file format starts the with magic bytes `UCIR`, a header, then a stream of `OP_FRAME` messages.

All numbers are little endian. Structures are densely-packed (no alignment).

Header
----

| name | type | desc |
|------|------|------|
| magic|      | `UCIR`
| version|uint32| File format version (0 for now)
| str\_arch | 32 bytes (null-padded) | Arch, such as "x86\_64", "x86", "mips", "sparc", "sparc64", "arm", "arm64"
| str\_os   | 32 bytes (null-padded) | OS, such as "linux", "darwin", "netbsd", "cgc"
| corder | uint8 | target code byte order. 0 = little endian, 1 = big endian |
| dorder | uint8 | target data byte order |

Messages
----

Each operation starts with a uint8 operation type followed by the message-specific header and data.

| name | type | desc |
|------|------|------|
| op   |uint8 | enum from the table below
| .... |varies| remainder of message

Message types
----

| ID | Name
|----|-------
| 0  | OP\_NOP
| 1  | OP\_FRAME
| 2  | OP\_KEYFRAME
| 3  | OP\_JMP
| 4  | OP\_STEP
| 5  | OP\_REG
| 6  | OP\_SPREG
| 7  | OP\_MEM\_READ
| 8  | OP\_MEM\_WRITE
| 9  | OP\_MEM\_MAP
| 10 | OP\_MEM\_UNMAP
| 11 | OP\_SYSCALL
| 12 | OP\_EXIT

Message Formats
====

OP\_NOP
----

Has no body. Does nothing.

| name | type | desc |
|------|------|------|
| op   |uint8 |OP\_NOP|

OP\_FRAME || OP\_KEYFRAME
----

Encapsulates a series of operations. Keyframes contain a collapsed representation of all ops from the subsequent non-key frame and are mostly useful for fast-forwarding. Always replay the first keyframe, even when not fast-forwarding, as it contains the binary setup.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_FRAME \|\| OP\_KEYFRAME
| pid  |uint64| process id (unique from first observation to the next OP\_EXIT)
| op\_count | uint32 | number of operations to follow
| data | .... | op\_count packed operations

OP\_JMP
----

A new basic block was entered. This updates the program counter to the first instruction in the block.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_JMP
| addr |uint64| block address
| size |uint32| block size (bytes)

OP\_STEP
----

An instruction executed at the program counter. The program counter will be incremented by the instruction size.
NOTE: if the instruction caused a jump, this won't be obvious until the following OP\_JMP.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_STEP
| size |uint8 | instruction size (bytes)

OP\_REG
----

A standard integer register value changed.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_REG
| num  |uint16| Unicorn register enum
| val  |uint64| New register value

OP\_SPREG
----

A special-type register value changed.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_SPREG
| num  |uint16| Unicorn register enum
| size |uint16| Size of special value
| val  |[]uint8| Byte array containing register value

OP\_MEM\_READ
----

Memory read performed. You must track memory writes to know the value.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_MEM\_READ
| addr |uint64| Memory address
| size |uint32| Size of read

OP\_MEM\_WRITE
----

Memory write performed.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_MEM\_WRITE
| addr |uint64| Memory address
| size |uint32| Size of write
| value|[]uint8| Byte array of memory written

OP\_MEM\_MAP
----

A new memory region was mapped, or the protection of an existing region was changed. This opcode does not zero memory unless the zero flag is set to 1.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_MEM\_MAP
| addr |uint64| Memory address
| size |uint32| Size of region
| prot |uint8 | Protection flags (RWX)
| zero |uint8 | (1) if region should be zeroed

OP\_MEM\_UNMAP
----

A memory region was unmapped.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_MEM\_UNMAP
| addr |uint64| Memory address
| size |uint32| Size of region

OP\_SYSCALL
----

A syscall happened. Implicit operations performed by the kernel such as memory writes, register modifications, and memory mapping will be combined into this message.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_SYSCALL
| num  |uint16| syscall number (os/kernel specific)
| ret  |uint64| return value
| arg\_count|uint8 | number of register arguments
| op\_count |uint16| number of operations
| args |[]uint64| dense array of syscall arguments
| ops  | []op | dense array of op messages

OP\_EXIT
----

The target terminated. If the frame's pid is observed again, it should be treated as a new process.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP\_EXIT
