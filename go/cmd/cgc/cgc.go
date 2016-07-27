package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/lunixbochs/usercorn/go"
	co "github.com/lunixbochs/usercorn/go/kernel/common"
	"github.com/lunixbochs/usercorn/go/models"
)

var secretPage uint64 = 0x4347c000
var secretSize uint64 = 0x1000

type Negotiate struct {
	Type    int
	in, out bytes.Buffer

	CS  []models.Usercorn
	POV models.Usercorn
}

func (no *Negotiate) Read(p []byte) (int, error) {
	n, err := no.out.Read(p)
	return n, err
}

func (no *Negotiate) Write(p []byte) (int, error) {
	en := binary.LittleEndian
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
	} else if no.Type > 0 {
		return 0, io.EOF
	}
	no.in.Write(p)
	if no.in.Len() >= 4 {
		no.Type = int(en.Uint32(no.in.Bytes()[:4]))
		log.Printf("Type %d POV requested", no.Type)
		if no.Type == 2 {
			out := make([]byte, 12)
			en.PutUint32(out[:4], uint32(secretPage))
			en.PutUint32(out[4:8], uint32(secretSize))
			en.PutUint32(out[8:12], 4)
			no.out.Write(out)
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

	var povFile = fs.String("pov", "", "")
	var idsFile = fs.String("ids", "", "")
	var idsDebug = fs.Bool("idsDebug", false, "")
	var trace = fs.Bool("trace", false, "")
	var btrace = fs.Bool("btrace", false, "")
	var etrace = fs.Bool("etrace", false, "")
	var mtrace = fs.Bool("mtrace", false, "")
	var mtrace2 = fs.Bool("mtrace2", false, "")
	var rtrace = fs.Bool("rtrace", false, "")
	var strace = fs.Bool("strace", false, "")

	var timeout = fs.Int("timeout", 0, "")

	fs.Parse(os.Args[1:])
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	setFlags := func(c *models.Config) {
		c.TraceBlock = *btrace
		c.TraceExec = *etrace || *trace
		c.TraceMem = *mtrace
		c.TraceMemBatch = *mtrace2 || *trace
		c.TraceReg = *rtrace || *trace
		c.TraceSys = *strace || *trace
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
			fmt.Printf("Error loading CB-%d (%s):\n", i, cb)
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

	var pov models.Usercorn
	if *povFile != "" {
		var err error
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

		povk.Virtio[1] = povk.Virtio[0]
		povk.Virtio[2] = &NullIO{}
		povk.Virtio[3] = &Negotiate{CS: cs, POV: pov}

		if *idsFile == "" {
			a, b := NewBufPipePair()
			cbio[0] = a
			povk.Virtio[0] = b
		} else {
			pov2cb, cb2pov, err := NewIDS(*idsFile, *idsDebug)
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
			<-time.After(time.Second * time.Duration(*timeout))
			for _, cb := range cs {
				cb.Stop()
			}
			if pov != nil {
				pov.Stop()
			}
		}()
	}
	var wg sync.WaitGroup
	for _, cb := range cs {
		wg.Add(1)
		go func() {
			cb.Run(nil, nil)
			wg.Done()
		}()
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
