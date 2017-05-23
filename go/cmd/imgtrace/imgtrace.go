package main

import (
	"fmt"
	"image/jpeg"
	"os"
	"path"

	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models/cpu"
)

func main() {
	c := cmd.NewUsercornCmd()
	var width *int
	var frameskip *int
	var outdir *string
	var binimg *bool
	var render *string
	var force *bool

	var memImg *memImage
	jpegOptions := &jpeg.Options{Quality: 90}

	frame := 0
	skip := 0
	memTrace := func(u cpu.Cpu, access int, addr uint64, size int, value int64) {
		var buf [8]byte
		b, _ := c.Usercorn.PackAddr(buf[:], uint64(value))
		memImg.traceMem(c.Usercorn, addr, b[:size])
		if value != 0 {
			memImg.dirty = true
		}
	}
	blockTrace := func(u cpu.Cpu, addr uint64, size uint32) {
		if !memImg.dirty {
			return
		}
		memImg.dirty = false

		if *frameskip > 0 {
			if skip < *frameskip {
				skip++
				return
			}
			skip = 0
		}
		frame++
		file, err := os.Create(path.Join(*outdir, fmt.Sprintf("%d.jpg", frame)))
		if err != nil {
			panic(err)
		}
		if err := jpeg.Encode(file, memImg.render(), jpegOptions); err != nil {
			panic(err)
		}
		file.Close()
	}
	c.SetupFlags = func() error {
		width = c.Flags.Int("size", 8, "block width (blocks are square)")
		outdir = c.Flags.String("out", "out/", "image output directory")
		binimg = c.Flags.Bool("binimg", false, "include binary+interpreter in trace")
		frameskip = c.Flags.Int("frameskip", 0, "only record every N image frames")
		render = c.Flags.String("render", "linear", "render type {linear, block, hilbert, digram}")
		force = c.Flags.Bool("force", false, "overwrite out directory")
		return nil
	}
	c.SetupUsercorn = func() error {
		var rtype int
		switch *render {
		case "linear":
			rtype = RENDER_LINEAR
		case "block":
			rtype = RENDER_BLOCK
		case "hilbert":
			rtype = RENDER_HILBERT
		case "digram":
			rtype = RENDER_DIGRAM
		default:
			return fmt.Errorf("unknown render type: %s", *render)
		}
		memImg = NewMemImage(*width, *width, rtype)

		if *force {
			os.RemoveAll(*outdir)
		}
		if err := os.Mkdir(*outdir, 0755); err != nil {
			return err
		}
		if _, err := c.Usercorn.HookAdd(cpu.HOOK_MEM_WRITE, memTrace, 1, 0); err != nil {
			return err
		}
		if _, err := c.Usercorn.HookAdd(cpu.HOOK_BLOCK, blockTrace, 1, 0); err != nil {
			return err
		}
		if *binimg {
			// pre-fill memory with binary
			for _, m := range c.Usercorn.Mappings() {
				mem, err := c.Usercorn.MemRead(m.Addr, m.Size)
				if err == nil {
					memImg.traceMem(c.Usercorn, m.Addr, mem)
				}
			}
		}
		return nil
	}
	c.Run(os.Args, os.Environ())
}
