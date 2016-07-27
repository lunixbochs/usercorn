package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
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

type Negotiate struct {
	Type    int
	in, out bytes.Buffer

	CB, POV models.Usercorn
}

func (no *Negotiate) Read(p []byte) (int, error) {
	n, err := no.out.Read(p)
	log.Printf("NEG -> POV: %s", hex.EncodeToString(p[:n]))
	return n, err
}

func (no *Negotiate) Write(p []byte) (int, error) {
	log.Printf("POV -> NEG: %s", hex.EncodeToString(p))
	en := binary.LittleEndian
	if no.Type == 2 {
		log.Printf("Type 2 POV result received: %s", hex.EncodeToString(p))
		mem, err := no.CB.MemRead(0x4347c000, 0x1000)
		if err == nil && bytes.Contains(mem, p) {
			log.Println("Type 2 success")
		} else {
			log.Println("Type 2 failed")
		}
		no.CB.Stop()
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
			en.PutUint32(out[:4], 0x4347c000)
			en.PutUint32(out[4:8], 0x1000)
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
	if len(os.Args) < 3 {
		fmt.Println("Usage: cgc CB POV")
		os.Exit(1)
	}

	cbConfig := &models.Config{
		Output: &WriteLogger{Prefix: "CB", Hex: false},
	}
	povConfig := &models.Config{
		Output: &WriteLogger{Prefix: "POV", Hex: false},
	}

	cb, err := usercorn.NewUsercorn(os.Args[1], cbConfig)
	if err != nil {
		fmt.Printf("Error loading CB:\n")
		fmt.Println(err)
		os.Exit(1)
	}

	pov, err := usercorn.NewUsercorn(os.Args[2], povConfig)
	if err != nil {
		fmt.Printf("Error loading POV:\n")
		fmt.Println(err)
		os.Exit(1)
	}

	cbk := &CgcHook{&co.KernelBase{}, make(map[co.Fd]io.ReadWriter), "CB"}
	cb.AddKernel(cbk, true)
	povk := &CgcHook{&co.KernelBase{}, make(map[co.Fd]io.ReadWriter), "POV"}
	pov.AddKernel(povk, true)

	cbp := NewBufPipe()
	povp := NewBufPipe()

	pov2cb := &WriteLogger{Prefix: "POV -> CB", Hex: true}
	cb2pov := &WriteLogger{Prefix: "CB -> POV", Hex: true}

	cbk.Virtio[0] = ReadWriter{io.TeeReader(cbp, pov2cb), povp}
	cbk.Virtio[1] = cbk.Virtio[0]
	cbk.Virtio[2] = &WriteLogger{Prefix: "CB[2]", Hex: true}

	povk.Virtio[0] = ReadWriter{io.TeeReader(povp, cb2pov), cbp}
	povk.Virtio[1] = povk.Virtio[0]
	povk.Virtio[2] = &WriteLogger{Prefix: "POV[2]", Hex: true}
	povk.Virtio[3] = &Negotiate{CB: cb, POV: pov}

	go func() {
		<-time.After(time.Second * 15)
		cb.Stop()
		pov.Stop()
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		pov.Run(nil, nil)
		wg.Done()
	}()
	go func() {
		cb.Run(nil, nil)
		wg.Done()
	}()
	wg.Wait()
}
