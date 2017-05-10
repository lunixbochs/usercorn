package trace

import (
	"github.com/golang/snappy"
	"github.com/lunixbochs/struc"
	"github.com/pkg/errors"
	"io"
	"strings"

	"github.com/lunixbochs/usercorn/go/arch"
	"github.com/lunixbochs/usercorn/go/models"
)

var TRACE_MAGIC = "UCIR"

type TraceHeader struct {
	// MAGIC ("UCIR")
	Magic string `struc:"[4]byte" json:"-"`
	// file format version
	Version uint32 `json:"version"`
	// Unicorn UC_ARCH and UC_MODE enums
	UcArch uint32 `json:"uc_arch"`
	UcMode uint32 `json:"uc_mode"`

	// Emulated architecture. Possible values include "x86_64", "x86", "mips", "arm", "arm64". Right-null-padded.
	Arch string `struc:"[32]byte" json:"arch"`

	// Emulated OS. Possible values include "linux", "darwin", "netbsd", "cgc", "dos". Right-null-padded.
	OS string `struc:"[32]byte" json:"os"`
}

type TraceWriter struct {
	w, zw io.WriteCloser
}

func NewWriter(w io.WriteCloser, u models.Usercorn) (*TraceWriter, error) {
	// TODO: handle errors here (with github.com/pkg/errors too)
	arch := u.Arch()
	header := &TraceHeader{
		Magic:   TRACE_MAGIC,
		Version: 1,
		UcArch:  uint32(arch.UC_ARCH),
		UcMode:  uint32(arch.UC_MODE),
		Arch:    u.Loader().Arch(),
		OS:      u.Loader().OS(),
	}
	if err := struc.Pack(w, header); err != nil {
		return nil, errors.Wrap(err, "failed to pack header")
	}
	zw := snappy.NewBufferedWriter(w)
	return &TraceWriter{w: w, zw: zw}, nil
}

// write a frame at a time
func (t *TraceWriter) Pack(frame models.Op) error {
	_, err := frame.Pack(t.zw)
	return err
}

func (t *TraceWriter) Close() {
	t.zw.Close()
	t.w.Close()
}

type TraceReader struct {
	r      io.ReadCloser
	zr     *snappy.Reader
	Header TraceHeader

	Arch *models.Arch
	OS   *models.OS
}

func NewReader(r io.ReadCloser) (*TraceReader, error) {
	t := &TraceReader{r: r}
	if err := struc.Unpack(r, &t.Header); err != nil {
		return nil, errors.Wrap(err, "failed to unpack header")
	}
	t.Header.Arch = strings.TrimRight(t.Header.Arch, "\x00")
	t.Header.OS = strings.TrimRight(t.Header.OS, "\x00")

	var err error
	t.Arch, t.OS, err = arch.GetArch(t.Header.Arch, t.Header.OS)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get arch/OS")
	}

	t.zr = snappy.NewReader(r)
	return t, nil
}

func (t *TraceReader) Next() (models.Op, error) {
	op, _, err := Unpack(t.zr)
	return op, err
}

func (t *TraceReader) Close() {
	t.zr.Reset(nil)
	t.r.Close()
}
