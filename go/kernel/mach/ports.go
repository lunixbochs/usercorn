package mach

func (k *Kernel) TaskSelfTrap() uint64 {
	return 1
}

func (k *Kernel) MachReplyPort() uint64 {
	return 1
}

func (k *Kernel) HostSelfTrap() uint64 {
	return 2
}

func (k *Kernel) MachMsgTrap() {}
