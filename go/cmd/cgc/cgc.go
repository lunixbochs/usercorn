package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/lunixbochs/usercorn/go"
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

var secretPage uint64 = 0x4347c000
var secretSize uint64 = 0x1000

func bitcount(i uint32) int {
	out := 0
	for bit := uint32(0); bit < 32; bit++ {
		if i&1<<bit != 0 {
			out++
		}
	}
	return out
}

type Negotiate struct {
	Type    int
	in, out bytes.Buffer
	ready   bool

	ipmask, regmask uint32
	ipval, regval   uint32

	regnum int

	CS  []models.Usercorn
	POV models.Usercorn
}

func (no *Negotiate) Read(p []byte) (int, error) {
	n, err := no.out.Read(p)
	return n, err
}

func (no *Negotiate) Write(p []byte) (int, error) {
	en := binary.LittleEndian
	if no.ready {
		if no.Type == 2 {
			log.Printf("Type 2 POV result received: %s", hex.EncodeToString(p))
			mem, err := no.CS[0].MemRead(secretPage, secretSize)
			if err == nil && bytes.Contains(mem, p) {
				log.Println("Type 2 success")
			} else {
				log.Println("Type 2 failed")
			}
			for _, cb := range no.CS {
				cb.Stop()
			}
			no.POV.Stop()
			return 0, nil
		} else {
			return 0, io.EOF
		}
	} else {
		if no.Type == 2 {
			return 0, io.EOF
		}
		no.in.Write(p)
		if no.Type == 0 && no.in.Len() >= 4 {
			var tmp [4]byte
			no.in.Read(tmp[:])
			no.Type = int(en.Uint32(tmp[:]))
			log.Printf("Type %d POV requested", no.Type)
			if no.Type == 2 {
				out := make([]byte, 12)
				en.PutUint32(out[:4], uint32(secretPage))
				en.PutUint32(out[4:8], uint32(secretSize))
				en.PutUint32(out[8:12], 4)
				no.out.Write(out)
				no.ready = true
			} else if no.Type != 1 {
				no.ready = true
				return 0, io.EOF
			}
		}
		if no.Type == 1 {
			if no.in.Len() < 12 {
				return len(p), nil
			} else {
				var tmp [12]byte
				no.in.Read(tmp[:])
				no.ipmask = en.Uint32(tmp[:4])
				no.regmask = en.Uint32(tmp[4:8])
				// bitcount was broken so is currently disabled
				/*
					if bitcount(no.ipmask) < 20 || bitcount(no.regmask) < 20 {
						log.Printf("Type 1 POV bitmask bit count too low:")
						log.Printf("ipmask: 0x%x  regmask: 0x%x", no.ipmask, no.regmask)
						no.Type = 0
						no.ready = true
						return 0, io.EOF
					}
				*/
				regmap := map[uint32]int{
					0: uc.X86_REG_EAX,
					1: uc.X86_REG_ECX,
					2: uc.X86_REG_EDX,
					3: uc.X86_REG_EBX,
					4: uc.X86_REG_ESP,
					5: uc.X86_REG_EBP,
					6: uc.X86_REG_ESI,
					7: uc.X86_REG_EDI,
				}
				regname := []string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"}
				regnum := en.Uint32(tmp[8:12])
				if num, ok := regmap[regnum]; ok {
					no.regnum = num
				} else {
					no.Type = 0
					no.ready = true
					return 0, io.EOF
				}
				// pick reg vals
				rand.Read(tmp[:4])
				no.ipval = en.Uint32(tmp[:4]) & no.ipmask
				rand.Read(tmp[:4])
				no.regval = en.Uint32(tmp[:4]) & no.regmask

				// send 'em
				en.PutUint32(tmp[:4], no.ipval)
				no.out.Write(tmp[:4])
				en.PutUint32(tmp[:4], no.regval)
				no.out.Write(tmp[:4])

				log.Printf("ipmask=0x%x  regmask=0x%x  regnum=0x%x (%s)\n", no.ipmask, no.regmask, no.regnum, regname[regnum])
				log.Printf(" ipval=0x%x   regval=0x%x\n", no.ipval, no.regval)
				no.ready = true
			}
		}
	}
	return len(p), nil
}

type CgcHook struct {
	*co.KernelBase
	Virtio map[co.Fd]io.ReadWriter
	Name   string
}

func (k *CgcHook) Transmit(fd co.Fd, buf co.Buf, size co.Len, ret co.Obuf) int {
	if rw, ok := k.Virtio[fd]; ok {
		mem, err := k.U.MemRead(buf.Addr, uint64(size))
		if err != nil {
			return -1
		}
		n, err := rw.Write(mem)
		if ret.Addr != 0 {
			if err := ret.Pack(int32(n)); err != nil {
				return -1
			}
		}
		if err != nil {
			return -1
		}
		return 0
	} else {
		fmt.Printf("%s: Transmit on unmapped fd %d\n", k.Name, fd)
		return -1
	}
}

func (k *CgcHook) Receive(fd co.Fd, buf co.Obuf, size co.Len, ret co.Obuf) int {
	if rw, ok := k.Virtio[fd]; ok {
		tmp := make([]byte, size)
		n, err := rw.Read(tmp)
		if err := buf.Pack(tmp[:n]); err != nil {
			fmt.Println("buf pack failed")
			return -1
		}
		if ret.Addr != 0 {
			if err := ret.Pack(int32(n)); err != nil {
				fmt.Println("n pack failed")
				return -1
			}
		}
		if err != nil {
			return -1
		}
		return 0
	} else {
		fmt.Printf("%s: Receive on unmapped fd %d\n", k.Name, fd)
		return -1
	}
}

func (k *CgcHook) Fdwait(nfds int, reads, writes, timeoutBuf co.Buf, readyFds co.Obuf) int {
	// Too bad.
	return -1
}

func main() {
	fs := flag.NewFlagSet("cgc", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: cgc [options] [-pov POV] [-ids IDS] CB [CB [CB...]]")
		fs.PrintDefaults()
	}

	var trace = fs.Bool("trace", false, "")
	var btrace = fs.Bool("btrace", false, "")
	var etrace = fs.Bool("etrace", false, "")
	var mtrace = fs.Bool("mtrace", false, "")
	// FIXME: victim of binary tracing
	// var mtrace2 = fs.Bool("mtrace2", false, "")
	var rtrace = fs.Bool("rtrace", false, "")
	var strace = fs.Bool("strace", false, "")
	var icount = fs.Bool("icount", false, "")

	var povFile = fs.String("pov", "", "")
	var idsFile = fs.String("ids", "", "")
	var idsDebug = fs.Bool("idsDebug", false, "")
	var flagtrace = fs.Bool("flagtrace", false, "trace secret flag page reads")
	var timeout = fs.Int("timeout", 0, "")

	fs.Parse(os.Args[1:])
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	setFlags := func(c *models.Config) {
		c.Trace.Everything = *trace
		c.Trace.Block = *btrace
		c.Trace.Ins = *etrace
		c.Trace.Mem = *mtrace
		c.Trace.Reg = *rtrace
		c.Trace.Sys = *strace
		// victim of binary trace rewrite
		// c.TraceMemBatch = *mtrace2 || *trace
	}

	log.SetFlags(log.Lmicroseconds)

	// TODO: IO logging should be done in Transmit/Receive and not in the pipes themselves
	// so we can track the source/dest CB
	// ...could just use strace for this?
	cbio := make(map[co.Fd]io.ReadWriter)

	// init CBs
	var cs []models.Usercorn
	for i, cb := range fs.Args() {
		name := fmt.Sprintf("CB-%d", i)
		config := &models.Config{
			Output: &WriteLogger{Prefix: name, Hex: false},
		}
		setFlags(config)
		u, err := usercorn.NewUsercorn(cb, config)
		if err != nil {
			fmt.Printf("Error loading %s (%s):\n", name, cb)
			fmt.Println(err)
			os.Exit(1)
		}
		cbk := &CgcHook{&co.KernelBase{}, cbio, name}
		u.AddKernel(cbk, true)
		cs = append(cs, u)
	}

	// create CB pipes
	if len(cs) > 1 {
		for i := range cs {
			a, b := NewBufPipePair()
			cbio[co.Fd(3+i*2)] = a
			cbio[co.Fd(4+i*2)] = b
		}
	}

	// give everyone in a CS the same secret page
	secret, _ := cs[0].MemRead(secretPage, secretSize)
	for _, u := range cs[1:] {
		u.MemWrite(secretPage, secret)
	}

	inscount := 0
	if *icount {
		var imut sync.Mutex
		for _, cb := range cs {
			cb.HookAdd(cpu.HOOK_CODE, func(_ cpu.Cpu, addr uint64, size uint32) {
				imut.Lock()
				inscount += 1
				imut.Unlock()
			}, 1, 0)
		}
		defer func() {
			fmt.Printf("\ninscount: %d\n", inscount)
		}()
	}

	if *flagtrace {
		for i, cb := range cs {
			name := fmt.Sprintf("CB-%d", i)
			cb.HookAdd(cpu.HOOK_MEM_READ, func(_ cpu.Cpu, access int, addr uint64, size int, val int64) {
				if addr >= secretPage && addr <= secretPage+0x1000 {
					eip, _ := cb.RegRead(uc.X86_REG_EIP)
					fmt.Printf("%s: FLAG READ eip: 0x%x addr: 0x%x size: %d\n", name, eip, addr, size)
				}
			}, 1, 0)
		}
	}

	var pov models.Usercorn
	var pov2cb, cb2pov *os.File
	var err error
	var neg *Negotiate
	if *povFile != "" {
		config := &models.Config{
			Output: &WriteLogger{Prefix: "POV", Hex: false},
		}
		setFlags(config)
		pov, err = usercorn.NewUsercorn(*povFile, config)
		if err != nil {
			fmt.Printf("Error loading POV (%s):\n", *povFile)
			fmt.Println(err)
			os.Exit(1)
		}
		povk := &CgcHook{&co.KernelBase{}, make(map[co.Fd]io.ReadWriter), "POV"}
		pov.AddKernel(povk, true)

		// set up POV IO
		cbio[2] = &NullIO{}

		neg = &Negotiate{CS: cs, POV: pov}
		povk.Virtio[1] = povk.Virtio[0]
		povk.Virtio[2] = &NullIO{}
		povk.Virtio[3] = neg

		if *idsFile == "" {
			a, b := NewBufPipePair()
			cbio[0] = a
			povk.Virtio[0] = b
		} else {
			pov2cb, cb2pov, err = NewIDS(*idsFile, *idsDebug)
			if err != nil {
				fmt.Println("Failed to set up IDS:", err)
				os.Exit(1)
			}
			cbio[0] = cb2pov
			povk.Virtio[0] = pov2cb
		}
		cbio[1] = cbio[0]
		povk.Virtio[1] = povk.Virtio[0]
	} else {
		// set up STDIO
		cbio[0] = os.Stdin
		cbio[1] = os.Stdout
		cbio[2] = os.Stderr
	}

	if *timeout > 0 {
		go func() {
			time.Sleep(time.Second * time.Duration(*timeout))
			log.Printf("Timeout (%d seconds) reached. Killing binaries.", *timeout)
			if *idsFile != "" {
				pov2cb.Close()
				cb2pov.Close()
			}
			for _, cb := range cs {
				cb.Stop()
			}
			if pov != nil {
				pov.Stop()
			}
			if *icount {
				fmt.Printf("\ninscount: %d\n", inscount)
			}
			os.Exit(0)
		}()
	}
	defer func() {
		if neg != nil && neg.Type == 1 {
			success := false
			for _, cb := range cs {
				eip, _ := cb.RegRead(uc.X86_REG_EIP)
				reg, _ := cb.RegRead(neg.regnum)
				if uint32(eip)&neg.ipmask == neg.ipval && uint32(reg)&neg.regmask == neg.regval {
					success = true
				}
			}
			if success {
				log.Println("Type 1 success")
			} else {
				log.Println("Type 1 failed")
			}
		}
	}()
	var wg sync.WaitGroup
	for _, cb := range cs {
		wg.Add(1)
		go func() {
			cb.Run(nil, nil)
			// if a CB goes down, take 'em all
			for _, cb := range cs {
				cb.Stop()
			}
			if pov != nil {
				pov.Stop()
			}
			wg.Done()
		}()
		if len(cs) > 1 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if pov != nil {
		wg.Add(1)
		go func() {
			pov.Run(nil, nil)
			wg.Done()
		}()
	}
	wg.Wait()
}
