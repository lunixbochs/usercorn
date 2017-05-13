package x86_64

import (
	"github.com/lunixbochs/ghostrace/ghost/sys/num"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"

	"github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/kernel/darwin"
	"github.com/lunixbochs/usercorn/go/models"

	"encoding/binary"
	"reflect"
	"strings"
	"time"
)

type DarwinKernel struct {
	*darwin.DarwinKernel
}

type NameMapEntry struct {
	id     int
	subMap map[string]NameMapEntry
}

var SysctlNameMapKern = map[string]NameMapEntry{
	"ostype":          {1, nil},
	"osrelease":       {2, nil},
	"osrevision":      {3, nil},
	"version":         {4, nil},
	"maxvnodes":       {5, nil},
	"maxproc":         {6, nil},
	"maxfiles":        {7, nil},
	"argmax":          {8, nil},
	"securelevel":     {9, nil},
	"hostname":        {10, nil},
	"hostid":          {11, nil},
	"clockrate":       {12, nil},
	"vnode":           {13, nil},
	"proc":            {14, nil},
	"file":            {15, nil},
	"profiling":       {16, nil},
	"posix1version":   {17, nil},
	"ngroups":         {18, nil},
	"job_control":     {19, nil},
	"saved_ids":       {20, nil},
	"boottime":        {21, nil},
	"nisdomainname":   {22, nil},
	"maxpartitions":   {23, nil},
	"kdebug":          {24, nil},
	"update":          {25, nil},
	"osreldate":       {26, nil},
	"ntp_pll":         {27, nil},
	"bootfile":        {28, nil},
	"maxfilesperproc": {29, nil},
	"maxprocperuid":   {30, nil},
	"dumpdev":         {31, nil}, /* we lie; don't print as int */
	"ipc":             {32, nil},

	"usrstack":   {35, nil},
	"logsigexit": {36, nil},
	"symfile":    {37, nil},
	"procargs":   {38, nil},

	"netboot":   {40, nil},
	"panicinfo": {41, nil},
	"sysv":      {42, nil},

	"exec":           {45, nil},
	"aiomax":         {46, nil},
	"aioprocmax":     {47, nil},
	"aiothreads":     {48, nil},
	"procargs2":      {49, nil},
	"corefile":       {50, nil},
	"coredump":       {51, nil},
	"sugid_coredump": {52, nil},
	"delayterm":      {53, nil},
	"shreg_private":  {54, nil},

	"low_pri_window":             {56, nil},
	"low_pri_delay":              {57, nil},
	"posix":                      {58, nil},
	"usrstack64":                 {59, nil},
	"nx":                         {60, nil},
	"tfp":                        {61, nil},
	"procname":                   {62, nil},
	"threadsigaltstack":          {63, nil},
	"speculative_reads_disabled": {64, nil},
	"osversion":                  {65, nil},
	"safeboot":                   {66, nil},
	"lctx":                       {67, nil},
	"rage_vnode":                 {68, nil},
	"tty":                        {69, nil},
	"check_openevt":              {70, nil},
	"thread_name":                {71, nil},
}

var SysctlNameMapVfs = map[string]NameMapEntry{
	"vfsconf": {0, nil},
}

var SysctlNameMapVm = map[string]NameMapEntry{
	"vmmeter": {1, nil},
	"loadavg": {2, nil},

	"swapusage": {5, nil},
}

var SysctlNameMapHw = map[string]NameMapEntry{
	"machine":       {1, nil},
	"model":         {2, nil},
	"ncpu":          {3, nil},
	"byteorder":     {4, nil},
	"physmem":       {5, nil},
	"usermem":       {6, nil},
	"pagesize":      {7, nil},
	"disknames":     {8, nil},
	"diskstats":     {9, nil},
	"epoch":         {10, nil},
	"floatingpoint": {11, nil},
	"machinearch":   {12, nil},
	"vectorunit":    {13, nil},
	"busfrequency":  {14, nil},
	"cpufrequency":  {15, nil},
	"cachelinesize": {16, nil},
	"l1icachesize":  {17, nil},
	"l1dcachesize":  {18, nil},
	"l2settings":    {19, nil},
	"l2cachesize":   {20, nil},
	"l3settings":    {21, nil},
	"l3cachesize":   {22, nil},
	"tbfrequency":   {23, nil},
	"memsize":       {24, nil},
	"availcpu":      {25, nil},
}

var SysctlNameMapUser = map[string]NameMapEntry{
	"cs_path":          {1, nil},
	"bc_base_max":      {2, nil},
	"bc_dim_max":       {3, nil},
	"bc_scale_max":     {4, nil},
	"bc_string_max":    {5, nil},
	"coll_weights_max": {6, nil},
	"expr_nest_max":    {7, nil},
	"line_max":         {8, nil},
	"re_dup_max":       {9, nil},
	"posix2_version":   {10, nil},
	"posix2_c_bind":    {11, nil},
	"posix2_c_dev":     {12, nil},
	"posix2_char_term": {13, nil},
	"posix2_fort_dev":  {14, nil},
	"posix2_fort_run":  {15, nil},
	"posix2_localedef": {16, nil},
	"posix2_sw_dev":    {17, nil},
	"posix2_upe":       {18, nil},
	"stream_max":       {19, nil},
	"tzname_max":       {20, nil},
}

var SysctlNameMapCTL = map[string]NameMapEntry{
	"kern":    {1, SysctlNameMapKern},
	"vm":      {2, SysctlNameMapVm},
	"vfs":     {3, SysctlNameMapVfs},
	"net":     {4, nil},
	"debug":   {5, nil},
	"hw":      {6, SysctlNameMapHw},
	"machdep": {7, nil},
	"user":    {8, SysctlNameMapUser},
}

func (k *DarwinKernel) Literal__sysctl(name common.Buf, namelen uint64, olddata common.Buf, oldlenp common.Buf, newdata common.Buf, newlen uint64) uint64 {
	//TODO: implement name-resolved sysctl invokations similar to syscalls
	result := 0
	mem, err := k.U.MemRead(name.Addr, namelen*4) //TODO: replace all occurences of "4" by "sizeof int" for the platform

	nameArr := make([]int, namelen)
	namelenInt := int(namelen)
	for i := 0; i < namelenInt; i++ {
		nameArr[i] = int(binary.LittleEndian.Uint32(mem[i*4 : (i+1)*4]))
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
	} else if namelen == 2 && nameArr[0] == 1 && nameArr[1] == 59 && newdata.Addr == 0 && newlen == 0 {
		//kern.usrstack64 query
		var usrstack64 uint64 = 0

		//search for the stack
		for _, m := range k.U.Mappings() {
			if m.Desc == "stack" {
				usrstack64 = uint64(m.Addr) + uint64(m.Size)
				break
			}
		}

		if usrstack64 == 0 {
			panic("stack not found")
		}

		olddata.Pack(usrstack64)
		datalen := uint32(reflect.TypeOf(usrstack64).Size())
		oldlenp.Pack(datalen)
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

		if result < 0 { // should be "if errorOccurred"
			eflags |= CF //set carry flag
		} else {
			eflags &= ^CF //unset carry flag
		}

		err = k.U.RegWrite(uc.X86_REG_EFLAGS, eflags)
		return err
	})
	return 0 //TODO: return actual error codes
}

func (k *DarwinKernel) SharedRegionCheckNp(startAddress uint64) uint64 {
	//TODO: actually implement
	return 1
}

func (k *DarwinKernel) BsdthreadRegister() uint64 {
	//TODO: implement
	return 0
}

func (k *DarwinKernel) Sigprocmask(how int32, mask common.Buf, omask common.Obuf) uint64 {
	/*
			"how" values:
		#    define SIG_UNBLOCK 1
		#    define SIG_BLOCK   2
		#    define SIG_SETMASK 3
	*/

	if mask.Addr != 0 {
		panic("Sigprocmask set not implemented")
	} else if omask.Addr != 0 {
		//query-only
		var blockedSigMask uint64 = 0
		omask.Pack(blockedSigMask)
	}

	return 0
}

type sigaltstack_t struct {
	Stackpointer uint64
	Size         int64
	Flags        int64
}

func (k *DarwinKernel) Sigaltstack(nss common.Buf, oss common.Obuf) uint64 {
	if nss.Addr != 0 {
		panic("Sigaltstack set not implemented")
	} else if oss.Addr != 0 {
		//query-only
		var altstack sigaltstack_t
		oss.Pack(&altstack)
	}

	return 0
}

type timeval_t struct {
	Tv_sec  int64
	Tv_usec int64
}

type timezone_t struct {
	Tz_minuteswest int64
	Tz_dsttime     int64 //daylight saving time
}

func (k *DarwinKernel) Gettimeofday(timeval common.Obuf, timezone common.Obuf) uint64 {
	if timeval.Addr != 0 {
		var timedata timeval_t
		now := time.Now()
		timedata.Tv_sec = now.Unix()
		timedata.Tv_usec = int64(now.Nanosecond()) / 1000
		timeval.Pack(&timedata)
	}

	if timezone.Addr != 0 {
		panic("gettimeofday timezone query not implemented")
	}

	return 0
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
	var addr_COMM_PAGE_VERSION uint64 = 0x00007fffffe00000 + 0x1e
	var addr_COMM_PAGE_GTOD_GENERATION uint64 = 0x00007fffffe00000 + 0x050 + 28
	var addr_COMM_PAGE_NT_GENERATION uint64 = 0x00007fffffe00000 + 0x050 + 24

	var commpageAddrBegin uint64 = 0x00007fffffe00000
	var commpageAddrEnd uint64 = 0x00007fffffe01fff
	if err := u.MemMap(commpageAddrBegin, commpageAddrEnd-commpageAddrBegin); err != nil {
		return err
	}
	u.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		if addr < commpageAddrBegin || addr > commpageAddrEnd {
			return
		}

		if access == uc.MEM_WRITE {
			u.Printf("\ncommpage Mem write")
		} else {
			u.Printf("\ncommpage Mem read")
			if addr == addr_COMM_PAGE_GTOD_GENERATION {
				//TODO: either write 0 in which case time lookups will fall back to syscalls
				//or write non-zero and write current timestamp to timestamp and timestampNanosecond fields
				var one uint32 = 1
				tmp := make([]byte, 4)
				binary.LittleEndian.PutUint32(tmp, one)
				u.MemWrite(addr_COMM_PAGE_NT_GENERATION, tmp)
			} else if addr == addr_COMM_PAGE_NT_GENERATION {
				//TODO: either write 0 in which case time lookups will fall back to syscalls
				//or write non-zero and write current timestamp to timestamp and timestampNanosecond fields
				var one uint32 = 1
				tmp := make([]byte, 4)
				binary.LittleEndian.PutUint32(tmp, one)
				u.MemWrite(addr_COMM_PAGE_NT_GENERATION, tmp)
			} else if addr == addr_COMM_PAGE_VERSION {
				//TODO: const value -> write only once?
				//or rewrite for protection if guest needs write-access on commpage somewhere
				var commpageThisVersion uint16 = 13
				tmp := make([]byte, 2)
				binary.LittleEndian.PutUint16(tmp, commpageThisVersion)
				u.MemWrite(addr_COMM_PAGE_VERSION, tmp)
			}
		}
		u.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
	}, commpageAddrBegin, commpageAddrEnd)

	//temp fix for missing AVX instructions: hook system functions which use them
	u.BreakAdd("__platform_bzero$VARIANT$Unknown", true, func(u models.Usercorn, addr uint64) {
		//zero memory
		dataAddr, _ := u.RegRead(AbiRegs[0])
		dataSize, _ := u.RegRead(AbiRegs[1])
		tmp := make([]byte, dataSize)
		u.MemWrite(dataAddr, tmp)

		//return
		retAddr, _ := u.Pop()
		u.RegWrite(u.Arch().PC, retAddr)
	})

	return AbiInit(u, DarwinSyscall)
}

func DarwinSyscall(u models.Usercorn) {
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
