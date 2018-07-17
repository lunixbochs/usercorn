package vlinux

import (
	"crypto/md5"
	"encoding/binary"
	"io"
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/posix"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/native/enum"
)

type File interface {
	io.ReadWriter
	io.Closer
	Stat() (os.FileInfo, error)
	Truncate(int64) error
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
	f, err := k.Fs.Open(path)
	if err != nil {
		return MinusOne
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return MinusOne
	}
	if mode&1 != 0 && stat.Mode()&1 == 0 {
		return MinusOne
	}
	if mode&2 != 0 && stat.Mode()&2 == 0 {
		return MinusOne
	}
	if mode&4 != 0 && stat.Mode()&4 == 0 {
		return MinusOne
	}
	return 0
}

// Fstat syscall
func (k *VirtualLinuxKernel) Fstat(fd co.Fd, buf co.Obuf) uint64 {
	f, ok := k.Fds[fd]
	if !ok {
		return MinusOne
	}
	stat, err := f.Stat()
	if err != nil {
		return MinusOne
	}
	return handleStat(buf, stat, k.U)
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

// Writev syscall
func (k *VirtualLinuxKernel) Writev(fd co.Fd, iov co.Buf, count uint64) uint64 {
	var written uint64
	for _, vec := range iovecIter(iov, count, k.U.Bits()) {
		data, _ := k.U.MemRead(vec.Base, vec.Len)
		n, err := syscall.Write(int(fd), data)
		if err != nil {
			return posix.Errno(err)
		}
		written += uint64(n)
	}
	return written
}

// Open syscall
func (k *VirtualLinuxKernel) Open(path string, flags enum.OpenFlag, mode uint64) uint64 {
	f, err := k.Fs.OpenFile(path, int(flags), os.FileMode(mode))
	if err != nil {
		return MinusOne
	}
	fd := k.nextfd
	k.nextfd++
	k.Fds[fd] = f
	return uint64(fd)
}

// Read syscall
func (k *VirtualLinuxKernel) Read(fd co.Fd, buf co.Obuf, size co.Len) uint64 {
	file, ok := k.Fds[fd]
	if !ok {
		return MinusOne
	}
	tmp := make([]byte, 1024)
	var n uint64
	for i := co.Len(0); i < size; i += 1024 {
		if i+1024 > size {
			tmp = tmp[:size-i]
		}
		count, err := file.Read(tmp)
		if err != nil {
			return posix.Errno(err)
		}
		if err := buf.Pack(tmp[:count]); err != nil {
			return MinusOne
		}
		n += uint64(count)
		if count < 1024 {
			break
		}
	}
	return n
}

// Close syscall
func (k *VirtualLinuxKernel) Close(fd co.Fd) uint64 {
	file, ok := k.Fds[fd]
	if !ok {
		return MinusOne
	}
	if err := file.Close(); err != nil {
		return MinusOne
	}
	return 0
}

// Stat syscall
func (k *VirtualLinuxKernel) Stat(path string, buf co.Obuf) uint64 {
	file, err := k.Fs.Open(path)
	if err != nil {
		return MinusOne
	}
	stat, err := file.Stat()
	if err != nil {
		return MinusOne
	}
	return handleStat(buf, stat, k.U)
}

func handleStat(buf co.Obuf, stat os.FileInfo, u models.Usercorn) uint64 {
	sum := md5.Sum([]byte(stat.Name()))
	ino := binary.BigEndian.Uint64(sum[:])
	s := &syscall.Stat_t{
		Ino:     ino,
		Size:    stat.Size(),
		Blksize: 1024,
	}
	posix.SetStatMode(s, int(stat.Mode()))
	return posix.HandleStat(buf, s, u, false)
}

func iovecIter(stream co.Buf, count uint64, bits uint) []posix.Iovec64 {
	res := []posix.Iovec64{}
	st := stream.Struc()
	for i := uint64(0); i < count; i++ {
		if bits == 64 {
			var iovec posix.Iovec64
			st.Unpack(&iovec)
			res = append(res, iovec)
		} else {
			var iv32 posix.Iovec32
			st.Unpack(&iv32)
			res = append(res, posix.Iovec64{
				Base: uint64(iv32.Base),
				Len:  uint64(iv32.Len),
			})
		}
	}
	return res
}
