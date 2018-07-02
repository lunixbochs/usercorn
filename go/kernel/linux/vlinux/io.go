package vlinux

import (
	"log"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
)

// File is used to represent files in the filesystem.
type File struct {
	Stat syscall.Stat_t
	Path string
	Data []byte
}

// Executable checks whether the file has exex permissions
func (f File) Executable() bool {
	return f.Stat.Mode&0x1 != 0
}

// Writable checks whether the file has write permissions
func (f File) Writable() bool {
	return f.Stat.Mode&0x2 != 0
}

// Readable checks whether the file has read permission
func (f File) Readable() bool {
	return f.Stat.Mode&0x4 != 0
}

// Fd holds all information about a virtual file descriptor
type Fd struct {
	File  *File
	write func(p []byte) (int, error)
}

func (f *Fd) Write(p []byte) (int, error) {
	return f.write(p)
}

// Readlink syscall
func (k *VirtualLinuxKernel) Readlink(path string, buf co.Obuf, size co.Len) uint64 {
	var name string
	if path == "/proc/self/exe" {
		name = k.U.Exe()
	} else {
		panic("Readlink not implemented")
	}
	if len(name) > int(size) {
		name = name[:size]
	}
	if err := buf.Pack([]byte(name)); err != nil {
		return MinusOne
	}
	return uint64(len(name))
}

// Access syscall
func (k *VirtualLinuxKernel) Access(path string, mode uint32) uint64 {
	file, ok := k.Files[path]
	if !ok {
		log.Printf("unable to access file %q", path)
		return MinusOne
	}
	if mode&0x1 != 0 && !file.Executable() {
		return MinusOne
	}
	if mode&0x2 != 0 && !file.Writable() {
		return MinusOne
	}
	if mode&0x4 != 0 && !file.Readable() {
		return MinusOne
	}
	return 0
}

// Fstat syscall
func (k *VirtualLinuxKernel) Fstat(fd co.Fd, buf co.Obuf) uint64 {
	vFd, ok := k.Fds[fd]
	if !ok {
		log.Printf("Invalid file descriptor %d", fd)
		return MinusOne
	}
	return posix.HandleStat(buf, &vFd.File.Stat, k.U, false)
}

// Write syscall
func (k *VirtualLinuxKernel) Write(fd co.Fd, buf co.Buf, size co.Len) uint64 {
	vFd, ok := k.Fds[fd]
	if !ok {
		return MinusOne
	}
	tmp := make([]byte, size)
	if err := buf.Unpack(tmp); err != nil {
		return MinusOne
	}
	n, err := vFd.Write(tmp)
	if err != nil {
		return MinusOne
	}
	return uint64(n)
}
