package x86_64

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/darwin"
	"github.com/lunixbochs/usercorn/go/models"
	
	"strings"
	"encoding/binary"
)

type DarwinKernel struct {
	*darwin.DarwinKernel
}

type NameMapEntry struct {
	id		int
	subMap	map[string]NameMapEntry
}

var SysctlNameMapKern = map[string]NameMapEntry{
	"ostype": 			NameMapEntry{1, nil},
	"osrelease":		NameMapEntry{2, nil},
	"osrevision":		NameMapEntry{3, nil},
	"version": 			NameMapEntry{4, nil},
	"maxvnodes":		NameMapEntry{5, nil},
	"maxproc": 			NameMapEntry{6, nil},
	"maxfiles": 		NameMapEntry{7, nil},
	"argmax": 			NameMapEntry{8, nil},
	"securelevel":		NameMapEntry{9, nil},
	"hostname": 		NameMapEntry{10, nil},
	"hostid": 			NameMapEntry{11, nil},
	"clockrate":		NameMapEntry{12, nil},
	"vnode": 			NameMapEntry{13, nil},
	"proc": 			NameMapEntry{14, nil},
	"file": 			NameMapEntry{15, nil},
	"profiling":		NameMapEntry{16, nil},
	"posix1version": 	NameMapEntry{17, nil},
	"ngroups": 			NameMapEntry{18, nil},
	"job_control": 		NameMapEntry{19, nil},
	"saved_ids": 		NameMapEntry{20, nil},
	"boottime": 		NameMapEntry{21, nil},
	"nisdomainname": 	NameMapEntry{22, nil},
	"maxpartitions": 	NameMapEntry{23, nil},
	"kdebug":			NameMapEntry{24, nil},
	"update":			NameMapEntry{25, nil},
	"osreldate": 		NameMapEntry{26, nil},
	"ntp_pll": 			NameMapEntry{27, nil},
	"bootfile": 		NameMapEntry{28, nil},
	"maxfilesperproc": 	NameMapEntry{29, nil},
	"maxprocperuid": 	NameMapEntry{30, nil},
	"dumpdev": 			NameMapEntry{31, nil},/* we lie; don't print as int */
	"ipc": 				NameMapEntry{32, nil},
	
	"usrstack": 		NameMapEntry{35, nil},
	"logsigexit": 		NameMapEntry{36, nil},
	"symfile": 			NameMapEntry{37, nil},
	"procargs": 		NameMapEntry{38, nil},
	
	"netboot": 			NameMapEntry{40, nil},
	"panicinfo":		NameMapEntry{41, nil},
	"sysv": 			NameMapEntry{42, nil},
	
	"exec": 			NameMapEntry{45, nil},
	"aiomax": 			NameMapEntry{46, nil},
	"aioprocmax": 		NameMapEntry{47, nil},
	"aiothreads": 		NameMapEntry{48, nil},
	"procargs2": 		NameMapEntry{49, nil},
	"corefile": 		NameMapEntry{50, nil},
	"coredump": 		NameMapEntry{51, nil},
	"sugid_coredump": 	NameMapEntry{52, nil},
	"delayterm": 		NameMapEntry{53, nil},
	"shreg_private": 	NameMapEntry{54, nil},
	
	"low_pri_window": 	NameMapEntry{56, nil},
	"low_pri_delay": 	NameMapEntry{57, nil},
	"posix": 			NameMapEntry{58, nil},
	"usrstack64": 		NameMapEntry{59, nil},
	"nx": 				NameMapEntry{60, nil},
	"tfp": 				NameMapEntry{61, nil},
	"procname": 		NameMapEntry{62, nil},
	"threadsigaltstack": 	NameMapEntry{63, nil},
	"speculative_reads_disabled": 	NameMapEntry{64, nil},
	"osversion": 		NameMapEntry{65, nil},
	"safeboot": 		NameMapEntry{66, nil},
	"lctx": 			NameMapEntry{67, nil},
	"rage_vnode": 		NameMapEntry{68, nil},
	"tty": 				NameMapEntry{69, nil},
	"check_openevt": 	NameMapEntry{70, nil},
	"thread_name": 		NameMapEntry{71, nil},
}

var SysctlNameMapVfs = map[string]NameMapEntry{
	"vfsconf": 			NameMapEntry{0, nil},
}

var SysctlNameMapVm = map[string]NameMapEntry{
	"vmmeter": 			NameMapEntry{1, nil},
	"loadavg": 			NameMapEntry{2, nil},
	
	"swapusage": 		NameMapEntry{5, nil},
}

var SysctlNameMapHw = map[string]NameMapEntry{
	"machine": 			NameMapEntry{1, nil},
	"model": 			NameMapEntry{2, nil},
	"ncpu": 			NameMapEntry{3, nil},
	"byteorder": 		NameMapEntry{4, nil},
	"physmem": 			NameMapEntry{5, nil},
	"usermem": 			NameMapEntry{6, nil},
	"pagesize": 		NameMapEntry{7, nil},
	"disknames": 		NameMapEntry{8, nil},
	"diskstats": 		NameMapEntry{9, nil},
	"epoch": 			NameMapEntry{10, nil},
	"floatingpoint": 	NameMapEntry{11, nil},
	"machinearch": 		NameMapEntry{12, nil},
	"vectorunit": 		NameMapEntry{13, nil},
	"busfrequency": 	NameMapEntry{14, nil},
	"cpufrequency": 	NameMapEntry{15, nil},
	"cachelinesize": 	NameMapEntry{16, nil},
	"l1icachesize": 	NameMapEntry{17, nil},
	"l1dcachesize": 	NameMapEntry{18, nil},
	"l2settings": 		NameMapEntry{19, nil},
	"l2cachesize": 		NameMapEntry{20, nil},
	"l3settings": 		NameMapEntry{21, nil},
	"l3cachesize": 		NameMapEntry{22, nil},
	"tbfrequency": 		NameMapEntry{23, nil},
	"memsize": 			NameMapEntry{24, nil},
	"availcpu": 		NameMapEntry{25, nil},
}

var SysctlNameMapUser = map[string]NameMapEntry{
	"cs_path": 				NameMapEntry{1, nil},
	"bc_base_max": 			NameMapEntry{2, nil},
	"bc_dim_max": 			NameMapEntry{3, nil},
	"bc_scale_max": 		NameMapEntry{4, nil},
	"bc_string_max": 		NameMapEntry{5, nil},
	"coll_weights_max": 	NameMapEntry{6, nil},
	"expr_nest_max": 		NameMapEntry{7, nil},
	"line_max": 			NameMapEntry{8, nil},
	"re_dup_max": 			NameMapEntry{9, nil},
	"posix2_version": 		NameMapEntry{10, nil},
	"posix2_c_bind": 		NameMapEntry{11, nil},
	"posix2_c_dev": 		NameMapEntry{12, nil},
	"posix2_char_term": 	NameMapEntry{13, nil},
	"posix2_fort_dev": 		NameMapEntry{14, nil},
	"posix2_fort_run":		NameMapEntry{15, nil},
	"posix2_localedef": 	NameMapEntry{16, nil},
	"posix2_sw_dev": 		NameMapEntry{17, nil},
	"posix2_upe": 			NameMapEntry{18, nil},
	"stream_max": 			NameMapEntry{19, nil},
	"tzname_max": 			NameMapEntry{20, nil},
}

var SysctlNameMapCTL = map[string]NameMapEntry{
	"kern": 	NameMapEntry{1, SysctlNameMapKern},
	"vm": 		NameMapEntry{2, SysctlNameMapVm},
	"vfs": 		NameMapEntry{3, SysctlNameMapVfs},
	"net": 		NameMapEntry{4, nil},
	"debug": 	NameMapEntry{5, nil},
	"hw": 		NameMapEntry{6, SysctlNameMapHw},
	"machdep": 	NameMapEntry{7, nil},
	"user": 	NameMapEntry{8, SysctlNameMapUser},
}

func (k *DarwinKernel) Literal__sysctl(name common.Buf, namelen uint64, olddata common.Buf, oldlenp common.Buf, newdata common.Buf, newlen uint64) uint64 {
	//TODO: implement name-resolved sysctl invokations similar to syscalls
	result := 0
	mem, err := k.U.MemRead(name.Addr, namelen * 4)//TODO: replace all occurences of "4" by "sizeof int" for the platform
	
	nameArr := make([]int, namelen)
	namelenInt := int(namelen)
	for i := 0; i < namelenInt; i++ {
		nameArr[i] = int(binary.LittleEndian.Uint32(mem[i*4:(i+1)*4]))
	}
	
	//special case magic numbers name == []int{0, 3} for sysctlByName: 
	//lookup actual name from namestring (given by newData)
	//reference: Libc sysctlbyname.c
	if namelen == 2 && nameArr[0] == 0 && nameArr[1] == 3 {
		nameStringBytes, _ := k.U.MemRead(newdata.Addr, newlen)
		nameString := string(nameStringBytes)
		k.U.Printf("nameString", nameString)
		k.U.Printf("\n")
		
		nameNodes := strings.Split(nameString, ".")
		nameMap := SysctlNameMapCTL
		oid := make([]int, len(nameNodes))
		oidBytes := make([]byte, len(oid)*4)
		for index, nodeName := range nameNodes {
			entry := nameMap[nodeName]
			oid[index] = entry.id
			binary.LittleEndian.PutUint32(oidBytes[index*4:(index+1)*4], uint32(entry.id))
			
			nameMap = entry.subMap
		}
		k.U.Printf("oid", oid, oidBytes)
		k.U.Printf("\n")
		
		
		k.U.MemWrite(olddata.Addr, oidBytes)
		oidlen := make([]byte, 4)
		binary.LittleEndian.PutUint32(oidlen, uint32(len(oidBytes)))
		k.U.MemWrite(oldlenp.Addr, oidlen)
	} else if namelen == 2 && nameArr[0] == 1 && nameArr[1] == 66 && newdata.Addr == 0 && newlen == 0 {
		//kern.safeboot query
		var safeboot uint32 = 0
		safebootBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(safebootBytes, safeboot)
		k.U.MemWrite(olddata.Addr, safebootBytes)
		safebootBytesLen := make([]byte, 4)
		binary.LittleEndian.PutUint32(safebootBytesLen, uint32(len(safebootBytes)))
		k.U.MemWrite(oldlenp.Addr, safebootBytesLen)
	} else {
		k.U.Printf("sysctl", nameArr, err)
		panic("unhandled sysctl")
	}
	k.U.Printf("mem, err", mem, err)
	k.U.Printf("\n")
	//TEMP (until we have proper syscall error reporting): error reporting via carry flag right here
	k.U.Trampoline(func() error {
		eflags, err := k.U.RegRead(uc.X86_REG_EFLAGS)
		//fmt.Printf("In Trampoline", eflags, err)
		
		const CF uint64 = 1 << 0
		
		if result < 0 {// should be "if errorOccurred"
			eflags |= CF //set carry flag
		} else {
			eflags &= ^CF //unset carry flag
		}
		
		err = k.U.RegWrite(uc.X86_REG_EFLAGS, eflags)
		return err
	})
	return 0//TODO: return actual error codes
}

func (k *DarwinKernel) SharedRegionCheckNp(startAddress uint64) uint64 {
	//TODO: actually implement
	return 1
}

func (k *DarwinKernel) ThreadFastSetCthreadSelf(addr uint64) uint64 {
	gsmsr := uint64(0xC0000101)
	Wrmsr(k.U, gsmsr, addr)
	
	return 0
}

func (k *DarwinKernel) Syscall(syscallNum int) uint64 {
	//TODO: check if there is such a thing as an "indirect indirect syscall" - in that case we need to fix this to support recursion
	syscallNum |= 0x2000000
	name, _ := num.Darwin_x86_mach[syscallNum]
	ret, _ := k.U.Syscall(syscallNum, name, common.RegArgsShifted(k.U, AbiRegs, 1))
	return ret
}

func DarwinKernels(u models.Usercorn) []interface{} {
	kernel := &DarwinKernel{darwin.NewKernel(u)}
	return []interface{}{kernel}
}

func DarwinInit(u models.Usercorn, args, env []string) error {
	if err := darwin.StackInit(u, args, env); err != nil {
		return err
	}
	
	//commpage
	//TODO: move constants
	var addr_COMM_PAGE_GTOD_GENERATION uint64
	addr_COMM_PAGE_GTOD_GENERATION = 0x00007fffffe00000 + 0x050 + 28
	var addr_COMM_PAGE_NT_GENERATION uint64
	addr_COMM_PAGE_NT_GENERATION = 0x00007fffffe00000 + 0x050 + 24
	
	var commpageAddrBegin uint64
	commpageAddrBegin = 0x00007fffffe00000
	var commpageAddrEnd uint64
	commpageAddrEnd = 0x00007fffffe01fff
	if err := u.MemMap(commpageAddrBegin, commpageAddrEnd - commpageAddrBegin); err != nil {
		return err
	}
	u.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		if access == uc.MEM_WRITE {
			u.Printf("\ncommpage Mem write")
		} else {
			u.Printf("\ncommpage Mem read")
			if addr == addr_COMM_PAGE_GTOD_GENERATION {
				//TODO: either write 0 in which case time lookups will fall back to syscalls
				//or write non-zero and write current timestamp to timestamp and timestampNanosecond fields
				one32 := []byte{1, 0, 0, 0}
				u.MemWrite(addr_COMM_PAGE_GTOD_GENERATION, one32)
			}
			if addr == addr_COMM_PAGE_NT_GENERATION {
				//TODO: either write 0 in which case time lookups will fall back to syscalls
				//or write non-zero and write current timestamp to timestamp and timestampNanosecond fields
				one32 := []byte{1, 0, 0, 0}
				u.MemWrite(addr_COMM_PAGE_NT_GENERATION, one32)
			}
		}
		u.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
	}, commpageAddrBegin, commpageAddrEnd)
	
	return AbiInit(u, DarwinSyscall)
}

func DarwinSyscall(u models.Usercorn) {
	//make result "success" (CF unset) by default
	//TODO: actually set CF depending on syscall failure/success
	u.Trampoline(func() error {
		eflags, err := u.RegRead(uc.X86_REG_EFLAGS)
		
		const CF uint64 = 1 << 0
		eflags &= ^CF //unset carry flag
		
		err = u.RegWrite(uc.X86_REG_EFLAGS, eflags)
		return err
	})
	
	rax, _ := u.RegRead(uc.X86_REG_RAX)
	name, _ := num.Darwin_x86_mach[int(rax)]
	ret, _ := u.Syscall(int(rax), name, common.RegArgs(u, AbiRegs))
	u.RegWrite(uc.X86_REG_RAX, ret)
}

func DarwinInterrupt(u models.Usercorn, intno uint32) {
	if intno == 0x80 {
		DarwinSyscall(u)
	}
}

func init() {
	Arch.RegisterOS(&models.OS{Name: "darwin", Kernels: DarwinKernels, Init: DarwinInit, Interrupt: DarwinInterrupt})
}
