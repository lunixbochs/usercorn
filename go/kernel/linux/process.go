package linux

func (k *LinuxKernel) Geteuid32() int {
	return k.PosixKernel.Geteuid()
}

func (k *LinuxKernel) Getuid32() int {
	return k.PosixKernel.Getuid()
}

func (k *LinuxKernel) Getgid32() int {
	return k.PosixKernel.Getgid()
}

func (k *LinuxKernel) Setgid32(gid int32) int {
	return k.PosixKernel.Setgid(int(gid))
}

func (k *LinuxKernel) Setuid32(uid int32) int {
	return k.PosixKernel.Setuid(int(uid))
}

func (k *LinuxKernel) Stat64() int {
	return 0
}
