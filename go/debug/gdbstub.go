package debug

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"github.com/pkg/errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lunixbochs/usercorn/go/models"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

func escape(p []byte) []byte {
	out := make([]byte, 0, len(p))
	for _, c := range p {
		if c == '#' || c == '$' || c == '}' {
			out = append(out, '}')
			out = append(out, c^0x20)
		} else {
			out = append(out, c)
		}
	}
	return out
}

func unescape(p []byte) []byte {
	out := make([]byte, 0, len(p))
	escaped := false
	for i, c := range p {
		if escaped {
			continue
		}
		if c == '{' && i < len(p)-1 {
			escaped = true
			out = append(out, p[i+1]^0x20)
		} else {
			out = append(out, c)
		}
	}
	return out
}

func checksum(p []byte) []byte {
	chk := 0
	for _, c := range p {
		chk = (chk + int(c)) % 256
	}
	return []byte(fmt.Sprintf("%02x", chk))
}

func parseRange(s string) (uint64, uint64) {
	tmp := strings.Split(s, ":")
	if len(tmp) == 0 {
		tmp = []string{s}
	}
	tmp = strings.Split(tmp[len(tmp)-1], ",")
	if len(tmp) != 2 {
		return 0, 0
	}
	a, _ := strconv.ParseUint(tmp[0], 16, 0)
	b, _ := strconv.ParseUint(tmp[1], 16, 0)
	return a, b
}

type Gdbstub struct {
	instances []models.Usercorn
}

func NewGdbstub(first models.Usercorn, extra ...models.Usercorn) *Gdbstub {
	instances := append([]models.Usercorn{first}, extra...)
	for _, u := range instances {
		u.Gate().Lock()
	}
	return &Gdbstub{instances}
}

func (d *Gdbstub) Run(c net.Conn) {
	fmt.Fprintf(os.Stderr, "GDB stub connected from %s\n", c.RemoteAddr())
	(&gdbClient{
		Conn: c,
		stub: d,
		u:    d.instances[0],

		breakpoints: make(map[uint64]cpu.Hook),

		verbose: false,
	}).Run()
}

type gdbClient struct {
	net.Conn
	noAck     bool
	noAckTest bool
	stub      *Gdbstub
	u         models.Usercorn

	regData  map[int]gdbReg
	regEnums map[int]int
	regList  []int

	breakpoints map[uint64]cpu.Hook

	verbose bool
}

func (c *gdbClient) fmtaddr(addr uint64) string {
	var tmp [8]byte
	packed, _ := c.u.PackAddr(tmp[:], addr)
	return hex.EncodeToString(packed)
}

func (c *gdbClient) Send(s string) error {
	if c.verbose {
		fmt.Printf("sending %v\n", s)
	}
	data := escape([]byte(s))
	data = []byte("$" + string(data) + "#" + string(checksum(data)))
	_, err := c.Write(data)
	return errors.Wrap(err, "gdbstub socket write failed")
}

func (c *gdbClient) Wait() {
	u := c.u
	pc, _ := u.RegRead(u.Arch().PC)
	c.Send(fmt.Sprintf("T%02xpc:%s;thread:1;", 0, c.fmtaddr(pc)))
}

func (c *gdbClient) Handle(cmdb []byte) error {
	if c.verbose {
		fmt.Printf("handling %v\n", string(cmdb))
	}
	u := c.u
	if len(cmdb) == 0 {
		return nil
	}
	b, rest := cmdb[0], string(cmdb[1:])
	var cmd, args string
	if strings.Contains(rest, ":") {
		tmp := strings.SplitN(rest, ":", 2)
		cmd, args = tmp[0], tmp[1]
	} else {
		cmd = rest
	}
	switch b {
	case 'q': // query
		switch cmd {
		case "Supported":
			c.Send("PacketSize=4000;qXfer:features:read+") // ;qXfer:memory-map:read+
		case "Attached":
			c.Send("1")
		case "Symbol":
			c.Send("OK")
		case "C":
			c.Send("OK")
		case "Xfer":
			if strings.HasPrefix(args, "features:read:target.xml:") {
				a, b := parseRange(args)
				tdesc := u.Arch().GdbXml
				if a >= 0 && a < uint64(len(tdesc)) {
					if a+b > uint64(len(tdesc)) {
						b = uint64(len(tdesc)) - a
					}
					c.Send("m" + tdesc[a:a+b])
				} else {
					c.Send("l")
				}
			} else {
				if c.verbose {
					fmt.Println("unknown q Xfer:", args)
				}
			}
		case "TStatus":
			c.Send("T0")
		case "Rcmd":
			tmp := strings.SplitN(cmd, ",", 2)
			if c.verbose {
				fmt.Println("would send input:", tmp[1])
			}
			// c.Send("O" + (output + "\n").encode("hex"))
			c.Send("OK")
		default:
			if c.verbose {
				fmt.Println("unknown cmd q", cmd, args)
			}
			c.Send("")
		}
	case 'Q': // set query
		switch cmd {
		case "StartNoAckMode":
			c.noAckTest = true
		default:
			if c.verbose {
				fmt.Println("unknown cmd Q", cmd, args)
			}
			c.Send("")
		}
	case 'v': // resume
		if cmd == "Cont?" {
			c.Send("")
		}
	case 'g': // read regs
		/*
			var vals []string
			for _, v := range c.regList {
				if v > 0 {
					enum := v - 1
					r, _ := u.RegRead(enum)
					vals = append(vals, c.fmtaddr(r))
				}
			}
			c.Send(strings.Repeat("0", 8))
			// c.Send(strings.Join(vals, ""))
		*/
		// FIXME
		c.Send("00000000")
	case 'G': // write regs
		if c.verbose {
			fmt.Println("should write regs")
		}
	case 'p': // read one reg
		i, _ := strconv.ParseUint(cmd, 16, 0)
		if int(i) < len(c.regList) {
			v := c.regList[i]
			if v > 0 {
				val, _ := u.RegRead(v - 1)
				c.Send(c.fmtaddr(val))
			} else {
				c.Send("00000000")
			}
		} else {
			c.Send("")
		}
	case 'm': // read memory
		a, b := parseRange(rest)
		mem, err := u.MemRead(a, b)
		if err != nil {
			if c.verbose {
				fmt.Println("error reading mem", err)
			}
			c.Send("")
		} else {
			c.Send(hex.EncodeToString(mem))
		}
	case 'M': // write memory
		a, _ := parseRange(rest)
		data, err := hex.DecodeString(rest)
		if err != nil {
			if c.verbose {
				fmt.Println("error parsing hex", rest, err)
			}
			c.Send("")
		} else {
			err := u.MemWrite(a, data)
			if err != nil {
				if c.verbose {
					fmt.Println("error writing mem", err)
				}
			}
		}
	case 'Z': // add breakpoint
		args := strings.Split(rest, ",")
		if len(args) != 3 {
			break
		}
		addr, _ := strconv.ParseUint(args[1], 16, 0)
		if _, ok := c.breakpoints[addr]; ok {
			c.Send("OK")
			break
		}
		h, _ := u.HookAdd(cpu.HOOK_CODE, func(_ cpu.Cpu, addr uint64, size uint32) {
			u.Trampoline(func() error { return nil })
		}, addr, addr+1)
		c.breakpoints[addr] = h
		c.Send("OK")
	case 'z': // remove breakpoint
		// TODO: this seems to freeze gdb
		args := strings.Split(rest, ",")
		if len(args) != 3 {
			break
		}
		addr, _ := strconv.ParseUint(args[1], 16, 0)
		if h, ok := c.breakpoints[addr]; ok {
			u.HookDel(h)
		}
		c.Send("OK")
	case 'c': // continue
		u.Gate().UnlockStopRelock()
		c.Wait()
	case 's': // step
		first := true
		h, _ := u.HookAdd(cpu.HOOK_CODE, func(_ cpu.Cpu, addr uint64, size uint32) {
			if first {
				first = false
			} else {
				u.Trampoline(func() error { return nil })
				return
			}
		}, 1, 0)
		u.Gate().UnlockStopRelock()
		u.HookDel(h)
		c.Wait()
	case '?': // last signal
		c.Wait()
	case 'H': // do thread op
		if c.verbose {
			fmt.Println("thread op", b, cmd, args)
		}
		c.Send("OK")
	case 'D': // detach
		return errors.New("detached")
	case 'T': // thread
		c.Send("OK")
	default:
		if c.verbose {
			fmt.Printf("unknown command %c %s %s\n", b, cmd, args)
		}
	}
	return nil
}

type gdbReg struct {
	XMLName xml.Name `xml:"reg"`
	Name    string   `xml:"name,attr"`
	Bitsize int      `xml:"bitsize,attr"`
	Type    string   `xml:"type,attr"`
	Regnum  int      `xml:"regnum,attr"`
}

type gdbTarget struct {
	XMLName xml.Name `xml:"target"`
	Regs    []gdbReg `xml:"feature>reg"`
}

func (c *gdbClient) parseXml(x string) {
	regLookup := make(map[string]int)
	c.regData = make(map[int]gdbReg)
	c.regEnums = make(map[int]int)

	var target gdbTarget
	xml.Unmarshal([]byte(x), &target)
	base := 0
	for i, v := range target.Regs {
		if v.Regnum > 0 {
			base = v.Regnum - i
		}
		c.regData[base+i] = v
		regLookup[v.Name] = base + i
	}
	a := c.u.Arch()
	regNames := a.RegNames()
	max := 0
	for enum, name := range regNames {
		if i, ok := regLookup[name]; ok {
			c.regEnums[i] = enum
			if i > max {
				max = i
			}
		}
	}
	c.regList = make([]int, max+1)
	for i, v := range c.regEnums {
		c.regList[i] = v + 1
	}
}

func (c *gdbClient) Run() {
	c.parseXml(c.u.Arch().GdbXml)

	input := bufio.NewReader(c)
	var err error

	var loop sync.Mutex
	go func() {
		for {
			loop.Lock()
			b, err := input.Peek(1)
			if err != nil {
				break
			}
			// TODO: this won't interrupt pending syscalls
			if b[0] == '\x03' {
				input.Discard(1)
				c.u.Trampoline(func() error { return nil })
			}
			loop.Unlock()
			<-time.After(100 * time.Millisecond)
		}
	}()

	loop.Lock()
	for {
		// Locking in this order simplifies loop flow, and guarantees lock is unlocked each iteration.
		loop.Unlock()
		loop.Lock()
		var b, chk []byte

		b, err = input.Peek(1)
		if err != nil {
			break
		} else if b[0] == 0x03 {
			continue
		} else if b[0] == '+' || b[0] == '-' {
			// ack
			input.Discard(1)
			if c.noAckTest && b[0] == '+' {
				c.noAck = true
			}
			c.noAckTest = false
		}
		if b, err = input.ReadBytes('#'); err != nil {
			break
		}
		if chk, err = input.Peek(2); err != nil {
			break
		}
		input.Discard(2)

		data := b[1 : len(b)-1]
		if bytes.Equal(checksum(data), chk) {
			c.ack('+')
			if err = c.Handle(unescape(data)); err != nil {
				break
			}
		} else {
			c.ack('-')
		}
	}
	loop.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "GDB stub error: %v\n", err)
	}
	c.Close()
}

func (c *gdbClient) ack(b byte) {
	if !c.noAck {
		c.Write([]byte{b})
	}
}
