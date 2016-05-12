Usercorn Replay Format
====

The disk file format starts the with magic bytes `UCIR`, a header, then a stream of `OP_FRAME` messages.

All numbers are big endian. No structure alignment is used.

Header
----

| name | type | desc |
|------|------|------|
| magic|      | `UCIR`
| version|uint32| Replay file format version (0 for now)
| arch |uint32| Unicorn architecture enum
| mode |uint32| Unicorn architecture mode
| str_arch | 32 bytes (null-padded) | Arch, such as "x86_64", "x86", "mips", "sparc", "sparc64", "arm", "arm64"
| str_os   | 32 bytes (null-padded) | OS, such as "linux", "darwin", "netbsd", "cgc"

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
| 0  | OP_NOP
| 1  | OP_FRAME
| 2  | OP_EXEC_ABS
| 3  | OP_EXEC_REL
| 4  | OP_REG_CHANGE
| 5  | OP_SPREG_CHANGE
| 6  | OP_MEM_READ
| 7  | OP_MEM_WRITE
| 8  | OP_MEM_MAP
| 9  | OP_MEM_UNMAP
| 10 | OP_SYSCALL
| 11 | OP_EXIT

Message Formats
====

OP_NOP
----

Has no body. Does nothing.

| name | type | desc |
|------|------|------|
| op   |uint8 |OP_NOP|

OP_FRAME
----

Contains a zlib-compressed series of messages. Keyframes contain a collapsed representation of all ops from the subsequent non-key frame and are mostly useful for fast-forwarding. Always replay the first keyframe, as it contains the binary setup.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_FRAME
| keyframe | uint8 | contains a non-zero value if this frame is a keyframe
| op_count | uint32 | number of operations contained in the compressed space
| size | uint32 | number of compressed bytes to follow
| data | .... | zlib-compressed bytes containing dense array of op messages

OP_EXEC_ABS
----

An instruction executed at an absolute address.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_EXEC_ABS
| addr |uint64| instruction address
| size |uint32| instruction size (bytes)

OP_EXEC_REL
----

An instruction executed at the address immediately following the last instruction.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_EXEC_ABS
| size |uint32| instruction size (bytes)

OP_REG_CHANGE
----

A standard integer register value changed.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_REG_CHANGE
| enum |uint16| Unicorn register enum
| value|uint64| New register value

OP_SPREG_CHANGE
----

A special-type register value changed.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_SPREG_CHANGE
| enum |uint16| Unicorn register enum
| size |uint16| Size of special value
| value|[]uint8| Byte array containing register value

OP_MEM_READ
----

Memory read performed.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_MEM_READ
| addr |uint64| Memory address
| size |uint64| Size of read
| value|[]uint8| Byte array of memory read


OP_MEM_WRITE
----

Memory write perform. The data format is identical to OP_MEM_READ.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_MEM_READ
| addr |uint64| Memory address
| size |uint64| Size of read
| value|[]uint8| Byte array of memory written

OP_MEM_MAP
----

A new memory region was mapped, or the protection of an existing region was changed. This opcode does not zero memory. If a remap zeroes memory (os-specific?), it will be represented as a MEM_MAP followed by a large MEM_WRITE containing zeroes.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_MEM_READ
| addr |uint64| Memory address
| size |uint32| Size of region
| prot |uint8 | Protection flags (RWX)

OP_MEM_UNMAP
----

A memory region was unmapped.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_MEM_READ
| addr |uint64| Memory address
| size |uint32| Size of region

OP_SYSCALL
----

A syscall happened. Implicit operations performed by the kernel such as memory writes, register modifications, and memory mapping will be combined into this message.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_SYSCALL
| num  |uint16| syscall number (os/kernel specific)
| ret  |uint64| return value
| arg_count|uint16| number of register arguments
| op_count |uint16| number of operations
| args |[]uint64| dense array of syscall arguments
| ops  | []op | dense array of op messages

OP_EXIT
----

The target terminated.

| name | type | desc |
|------|------|------|
| op   |uint8 | OP_EXIT
