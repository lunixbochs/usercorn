package posix

import (
	"os"
	"syscall"

	co "github.com/lunixbochs/usercorn/go/kernel/common"
)

func (k *PosixKernel) Exit(code int) {
	k.U.Exit(code)
}

func (k *PosixKernel) ExitGroup(code int) {
	k.Exit(code)
}

func (k *PosixKernel) Getpid() int {
	return os.Getpid()
}

func (k *PosixKernel) Getppid() int {
	return os.Getppid()
}

func (k *PosixKernel) Kill(pid, signal int) uint64 {
	// TODO: os-specific signal handling?
	return Errno(syscall.Kill(pid, syscall.Signal(signal)))
}

func (k *PosixKernel) Execve(path string, argvBuf, envpBuf co.Buf) uint64 {
	// TODO: put this function somewhere generic?
	readStrArray := func(buf co.Buf) []string {
		var out []string
		for {
			var addr uint64
			if k.U.Bits() == 64 {
				buf.Unpack(&addr)
			} else {
				var addr32 uint32
				buf.Unpack(&addr32)
				addr = uint64(addr32)
			}
			if addr == 0 {
				break
			}
			s, _ := k.U.Mem().ReadStrAt(addr)
			out = append(out, s)
		}
		return out
	}
	argv := readStrArray(argvBuf)
	envp := readStrArray(envpBuf)
	return Errno(syscall.Exec(path, argv, envp))
}
