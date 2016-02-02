package posix

func (k *PosixKernel) Ioctl()         {}
func (k *PosixKernel) RtSigprocmask() {}
func (k *PosixKernel) RtSigaction()   {}
func (k *PosixKernel) Futex()         {}
func (k *PosixKernel) Fcntl()         {}
func (k *PosixKernel) SchedYield()    {}
func (k *PosixKernel) Madvise()       {}
func (k *PosixKernel) Mlock()         {}
func (k *PosixKernel) Munlock()       {}
func (k *PosixKernel) Mlockall()      {}
func (k *PosixKernel) Munlockall()    {}

func (k *PosixKernel) Swapon()  {}
func (k *PosixKernel) Swapoff() {}
