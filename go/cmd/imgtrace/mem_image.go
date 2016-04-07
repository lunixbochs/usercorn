package main

import (
	"image"
	"image/color"
	"image/color/palette"
	"math"
	"sort"

	"github.com/lunixbochs/usercorn/go/models"
)

type region struct {
	Addr, Size     uint64
	Filename, Desc string

	Prot      int
	Pixels    []color.RGBA
	ByteCount int
}

func (r *region) Contains(addr uint64) bool {
	return addr >= r.Addr && addr < r.Addr+r.Size
}

type RegionAddrSort []*region

func (r RegionAddrSort) Len() int           { return len(r) }
func (r RegionAddrSort) Less(i, j int) bool { return r[i].Addr < r[j].Addr }
func (r RegionAddrSort) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

const (
	RENDER_LINEAR = iota
	RENDER_BLOCK
	RENDER_HILBERT
	RENDER_DIGRAM
)

type memImage struct {
	maps          []*region
	lastMap       int
	dirty         bool
	width, height int
	renderType    int

	blockWidth, blockHeight int
	blockSize               int
}

func NewMemImage(blockWidth, blockHeight, renderType int) *memImage {
	return &memImage{
		blockWidth:  blockWidth,
		blockHeight: blockHeight,
		blockSize:   blockWidth * blockHeight,
		renderType:  renderType,
	}
}

func (p *memImage) ColorModel() color.Model {
	return color.RGBAModel
}

func (p *memImage) Bounds() image.Rectangle {
	return image.Rect(0, 0, p.width*p.blockWidth, p.height*p.blockHeight)
}

func (p *memImage) At(x, y int) color.Color {
	// TODO: borders?
	rtype := p.renderType
	if rtype == RENDER_HILBERT {
		d := 0
		hx, hy := x%p.blockWidth, y%p.blockHeight
		// reset to block origin
		x -= hx
		y -= hy
		var rotx, roty int
		for s := p.blockWidth / 2; s > 0; s /= 2 {
			if hx&s > 0 {
				rotx = 1
			}
			if hy&s > 0 {
				roty = 1
			}
			d += s * s * ((3 * rotx) ^ roty)
			if roty == 0 {
				if rotx == 1 {
					hx = p.blockWidth - 1 - hx
					hy = p.blockWidth - 1 - hy
				}
				hx, hy = hy, hx
			}
		}
		rtype = RENDER_BLOCK
		// reapply hilbert coords
		x += hx
		y += hy
	}
	switch rtype {
	case RENDER_LINEAR:
		pix := (x + y*p.blockWidth*p.width)
		pos := pix / p.blockSize
		if pos >= len(p.maps) {
			return color.Black
		}
		return p.maps[pos].Pixels[pix%p.blockSize]
	case RENDER_BLOCK:
		// TODO: block render is broken when approaching bottom right
		col := x / p.blockWidth
		row := y / p.blockHeight
		if col < 0 || col >= p.height || row < 0 || row >= p.width {
			return color.Black
		}
		pos := row*p.width + col
		if pos >= len(p.maps) {
			return color.Black
		}
		// look up pixel in block
		block := p.maps[pos]
		pix := (x % p.blockWidth) + (y%p.blockHeight)*p.blockWidth
		if pix > p.blockSize {
			return color.Black
		}
		return block.Pixels[pix]
	default:
		return color.Black
	}
}

func (p *memImage) render() image.Image {
	return p
}

func (p *memImage) resize() {
	// bias toward width over height
	fcount := float64(len(p.maps))
	p.height = int(math.Ceil(fcount / math.Sqrt(fcount)))
	p.width = int(math.Ceil(fcount / float64(p.height)))
}

func (p *memImage) find(addr uint64) (int, *region, bool) {
	if len(p.maps) == 0 {
		return 0, nil, false
	}
	if p.lastMap >= 0 && p.lastMap < len(p.maps) && p.maps[p.lastMap].Contains(addr) {
		return p.lastMap, p.maps[p.lastMap], true
	}
	maps := p.maps
	// do a binary search
	low := 0
	for len(maps) > 1 {
		pivot := len(maps) / 2
		if addr < maps[pivot].Addr {
			maps = maps[:pivot]
		} else {
			maps = maps[pivot:]
			low += pivot
		}
	}
	if len(maps) == 1 && maps[0].Contains(addr) {
		p.lastMap = low
		return low, maps[0], true
	}
	return 0, nil, false
}

func (p *memImage) traceMem(u models.Usercorn, addr uint64, data []byte) {
	if len(data) > p.blockSize {
		firstLen := (addr+uint64(p.blockSize)-1) & ^uint64(p.blockSize-1) - addr
		if firstLen > 0 {
			p.traceMem(u, addr, data[:firstLen])
		}
		for i := firstLen; i < uint64(len(data)); i += uint64(p.blockSize) {
			p.traceMem(u, addr+uint64(i), data[i:i+uint64(p.blockSize)])
		}
		return
	}

	i, m, had := p.find(addr)
	if !had {
		aligned := addr & ^uint64(p.blockSize-1)
		r := &region{Addr: aligned, Size: uint64(p.blockSize), Pixels: make([]color.RGBA, p.blockSize)}
		for _, v := range u.Mappings() {
			if v.Contains(addr) {
				r.Desc = v.Desc
				r.Prot = v.Prot
				if v.File != nil {
					r.Filename = v.File.Name
				}
				break
			}
		}
		p.maps = append(p.maps, r)
		sort.Sort(RegionAddrSort(p.maps))

		i, m, _ = p.find(addr)
		p.resize()
	}
	off := (addr - m.Addr)
	dst := m.Pixels[off:]
	for i, v := range data {
		if (dst[i].A == 0) != (v == 0) {
			if v != 0 {
				m.ByteCount++
			} else {
				m.ByteCount--
			}
		}
		if v == 0 {
			dst[i].A = 0
		} else {
			dst[i].A = 255
			dst[i] = palette.WebSafe[v%216].(color.RGBA)
			/*
				if m.Desc == "interp" {
					dst[i].R = v & 0x0F
					dst[i].G = v & 0xF0
				} else if m.Desc == "exe" {
					dst[i].B = v
				} else if m.Desc == "stack" {
					dst[i].G = v
				} else {
					dst[i] = palette.WebSafe[v%216].(color.RGBA)
				}
			*/
		}
	}
	if m.ByteCount == 0 {
		p.maps = append(p.maps[:i], p.maps[i+1:]...)
		p.resize()
	}
}
