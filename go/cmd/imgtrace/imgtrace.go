package main

import (
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"image"
	"image/color"
	"image/color/palette"
	"image/png"
	"math"
	"os"
	"path"
	"sort"

	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models"
)

const PageSize = 128
const ImgLine = PageSize * 4

type imageProxy struct {
	*image.RGBA
	maps  []*models.Mmap
	dirty bool
}

func (p *imageProxy) resize() {
	size := len(p.maps) * PageSize
	dim := int(math.Ceil(math.Sqrt(float64(size))))
	p.Rect = image.Rect(0, 0, dim, dim)
	p.Stride = dim * 4
}

func (p *imageProxy) find(addr uint64) (int, *models.Mmap, bool) {
	for i, m := range p.maps {
		if m.Contains(addr) {
			return i, m, true
		}
	}
	return 0, nil, false
}

func (p *imageProxy) traceMem(addr uint64, data []byte) {
	i, m, had := p.find(addr)
	if !had {
		// TODO: copy desc/prot/etc from real mapping?
		aligned := addr & ^uint64(PageSize-1)
		p.maps = append(p.maps, &models.Mmap{Addr: aligned, Size: PageSize})
		sort.Sort(models.MmapAddrSort(p.maps))

		i, m, _ = p.find(addr)
		p.Pix = append(append(p.Pix[:i*ImgLine], make([]byte, ImgLine)...), p.Pix[i*ImgLine:]...)
		p.resize()
	}
	off := (addr - m.Addr) * 4
	line := p.Pix[i*ImgLine : (i+1)*ImgLine]
	dst := line[off:]
	for _, v := range data {
		if v == 0 {
			dst[3] = 0
		} else {
			c := palette.Plan9[v].(color.RGBA)
			dst[0] = uint8(c.R)
			dst[1] = uint8(c.G)
			dst[2] = uint8(c.B)
			dst[3] = uint8(c.A)
		}
		dst = dst[4:]
	}
	// delete empty lines
	for i := 3; i < len(line); i += 4 {
		if line[i] > 0 {
			return
		}
	}
	p.maps = append(p.maps[:i], p.maps[i+1:]...)
	p.Pix = append(p.Pix[:i*ImgLine], p.Pix[(i+1)*ImgLine:]...)
	p.resize()
}

func main() {
	c := cmd.NewUsercornCmd()
	var width, height *int
	var outdir *string

	// height is overallocated to allow for sloppy resizing
	memImg := &imageProxy{RGBA: image.NewRGBA(image.Rect(0, 0, PageSize, 16))}

	frame := 0
	memTrace := func(u uc.Unicorn, access int, addr uint64, size int, value int64) {
		var buf [8]byte
		b, _ := c.Usercorn.PackAddr(buf[:], uint64(value))
		memImg.traceMem(addr, b[:size])
		if value != 0 {
			memImg.dirty = true
		}
	}
	blockTrace := func(u uc.Unicorn, addr uint64, size uint32) {
		if !memImg.dirty {
			return
		}
		memImg.dirty = false

		frame++
		file, err := os.Create(path.Join(*outdir, fmt.Sprintf("%d.png", frame)))
		if err != nil {
			panic(err)
		}
		if err := png.Encode(file, memImg); err != nil {
			panic(err)
		}
		file.Close()
	}
	c.SetupFlags = func() error {
		width = c.Flags.Int("width", 1024, "video width")
		height = c.Flags.Int("height", 768, "video height")
		outdir = c.Flags.String("out", "out/", "image output directory")
		return nil
	}
	c.SetupUsercorn = func() error {
		if err := os.Mkdir(*outdir, 0755); err != nil {
			return err
		}
		if _, err := c.Usercorn.HookAdd(uc.HOOK_MEM_WRITE, memTrace, 1, 0); err != nil {
			return err
		}
		if _, err := c.Usercorn.HookAdd(uc.HOOK_BLOCK, blockTrace, 1, 0); err != nil {
			return err
		}
		// pre-fill memory with binary
		for _, m := range c.Usercorn.Mappings() {
			mem, err := c.Usercorn.MemRead(m.Addr, m.Size)
			if err == nil {
				for i := 0; i < len(mem); i += PageSize {
					memImg.traceMem(m.Addr+uint64(i), mem[i:i+PageSize])
				}
			}
		}
		return nil
	}
	c.Run(os.Args, os.Environ())
}
