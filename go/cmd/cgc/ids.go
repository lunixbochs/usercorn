package main

import (
	"os"
	"os/exec"
	"syscall"
)

func newFile(fd int) *os.File {
	return os.NewFile(uintptr(fd), "")
}

func NewIDS(rules string, debug bool) (*os.File, *os.File, error) {
	pair1, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	pair2, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}

	pov2cb := newFile(pair1[0])
	cb2pov := newFile(pair2[0])

	args := []string{"--rules", rules}
	if debug {
		args = append(args, "--debug")
	}
	cmd := exec.Command("cb-proxy-samurai", args...)
	cmd.ExtraFiles = []*os.File{newFile(pair1[1]), newFile(pair2[1])}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return pov2cb, cb2pov, nil
}
