package main

import (
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"image"
	"image/color/palette"
	"image/jpeg"
	"math"
	"os"
	"path"
	"sort"

	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models"
)

func drawFrame(u models.Usercorn, width, height int) image.Image {
	maps := u.Mappings()
	sort.Sort(models.MmapAddrSort(maps))

	sp, _ := u.RegRead(u.Arch().SP)
	var size uint64
	for _, m := range maps {
		if m.Desc == "stack" {
			size += (m.Addr + m.Size) - sp
		} else {
			size += m.Size
		}
	}
	dim := int(math.Ceil(math.Sqrt(float64(size))))
	if dim%2 == 1 {
		dim++
	}
	img := image.NewRGBA(image.Rect(0, 0, dim, dim))
	offset := 0
	for _, m := range maps {
		var mem []byte
		var err error
		if m.Desc == "stack" {
			spAligned := sp & ^uint64(0xFFF)
			if spAligned < m.Addr {
				spAligned = m.Addr
			}
			mem, err = u.MemRead(spAligned, m.Addr+m.Size-spAligned)
		} else {
			mem, err = u.MemRead(m.Addr, m.Size)
		}
		if err != nil {
			panic(err)
		} else {
			for _, v := range mem {
				if v != 0 {
					x := offset % dim
					y := offset / dim
					img.Set(x, y, palette.Plan9[v])
				}
				offset++
			}
		}
	}
	return img
}

func main() {
	c := cmd.NewUsercornCmd()
	var width, height *int
	var outdir *string

	jpegOptions := &jpeg.Options{Quality: 70}

	frame := 0
	blockTrace := func(u uc.Unicorn, addr uint64, size uint32) {
		frame++
		img := drawFrame(c.Usercorn, *width, *height)
		file, err := os.Create(path.Join(*outdir, fmt.Sprintf("%d.jpg", frame)))
		if err != nil {
			panic(err)
		}
		if err := jpeg.Encode(file, img, jpegOptions); err != nil {
			panic(err)
		}
		file.Close()
	}
	c.SetupFlags = func() error {
		width = c.Flags.Int("width", 1024, "video width")
		height = c.Flags.Int("height", 768, "video height")
		outdir = c.Flags.String("out", "out/", "jpg output directory")
		return nil
	}
	c.SetupUsercorn = func() error {
		if err := os.Mkdir(*outdir, 0755); err != nil {
			return err
		}

		_, err := c.Usercorn.HookAdd(uc.HOOK_BLOCK, blockTrace, 1, 0)
		if err != nil {
			return err
		}
		return nil
	}
	c.Run(os.Args, os.Environ())
}
