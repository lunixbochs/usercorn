package linux

func (k *LinuxKernel) Getuid32() int {
	return k.PosixKernel.Getuid()
}

func (k *LinuxKernel) Stat64() int {
	return 0
}
