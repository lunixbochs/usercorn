package mach

func (k *MachKernel) TaskSelfTrap() uint64 {
	return 1
}

func (k *MachKernel) MachReplyPort() uint64 {
	return 1
}

func (k *MachKernel) HostSelfTrap() uint64 {
	return 2
}

func (k *MachKernel) MachMsgTrap() {}
