package mach

func (k *Kernel) Literal__thread_selfid() uint64 {
	return 1
}

/* TODO: move this to arch/OS subkernel
func thread_fast_set_cthread_self(u syscalls.U, a []uint64) uint64 {
	u.RegWrite(uc.X86_REG_GS, a[0])
	return 0
}
*/
