package fuzz

import (
	"encoding/binary"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime/debug"
	"sync"
	"syscall"
	"unsafe"

	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

/*
#include <stdlib.h>
#include <sys/shm.h>
#include <string.h>

#include <unicorn/unicorn.h>
#cgo LDFLAGS: -lunicorn

void *afl_setup() {
	char *id = getenv("__AFL_SHM_ID");
	if (id == NULL) {
		return NULL;
	}
	void *afl_area = shmat(atoi(id), NULL, 0);
	if (afl_area == (void *)-1) {
		return NULL;
	}
	return afl_area;
}

typedef struct {
	uint64_t prev;
	uint8_t *area;
	uint64_t size;
	uc_hook hh;
} afl_state;

uint64_t murmur64(uint64_t val) {
	uint64_t h = val;
	h ^= val >> 33;
	h *= 0xff51afd7ed558ccd;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53;
	h ^= h >> 33;
	return h;
}

void afl_block_cb(uc_engine *uc, uint64_t addr, uint32_t size, void *user) {
	afl_state *state = user;
	// size must be a power of two
	uint64_t cur = murmur64(addr) & (state->size - 1);
	state->area[cur ^ state->prev]++;
	state->prev = cur;
}

afl_state *afl_uc_hook(void *uc, void *area, uint64_t size) {
	afl_state *state = malloc(sizeof(afl_state));
	state->area = area;
	state->size = size;
	if (uc_hook_add(uc, &state->hh, UC_HOOK_BLOCK, afl_block_cb, state, 1, 0) != UC_ERR_OK) {
		free(state);
		return NULL;
	}
	return state;
}
*/
import "C"

var MAP_SIZE uint64 = 1 << 16
var FORKSRV_FD = 198
var aflHello = []byte{1, 2, 3, 4}

type FakeProc struct {
	Argv     []string
	Stdin    io.WriteCloser
	Usercorn models.Usercorn
	*exec.Cmd
	sync.Mutex
}

func (p *FakeProc) Start() error {
	p.Lock()
	defer p.Unlock()
	if p.Cmd != nil {
		// kill(0) to see if it's still running
		if p.Process.Signal(syscall.Signal(0)) == nil {
			return nil
		}
	}
	var err error
	p.Cmd = exec.Command(p.Argv[0], p.Argv[1:]...)
	p.Stdin, err = p.StdinPipe()
	if err != nil {
		p.Usercorn.Printf("failed to open stdin: %s\n", err)
		return errors.Wrap(err, "failed to open stdin")
	}
	if err = p.Cmd.Start(); err != nil {
		p.Usercorn.Printf("failed to spawn child: %s\n", err)
		return errors.Wrap(err, "failed to spawn child")
	}
	go func() {
		p.Wait()
		p.Lock()
		defer p.Unlock()
		p.Usercorn.Stop()
		p.Stdin.Close()
		p.Cmd = nil
	}()
	return nil
}

func Main(args []string) {
	message := []byte("In fuzz main")
	ioutil.WriteFile("/tmp/outfile", message, 0444)

	forksrvCtrl := os.NewFile(uintptr(FORKSRV_FD), "afl_ctrl")
	forksrvStatus := os.NewFile(uintptr(FORKSRV_FD+1), "afl_status")

	c := cmd.NewUsercornCmd()
	var forkAddr *uint64
	var fuzzInterp *bool

	nofork := os.Getenv("AFL_NO_FORKSRV") == "1"

	aflArea := C.afl_setup()
	if aflArea == nil {
		panic("could not set up AFL shared memory")
	}

	c.SetupFlags = func() error {
		forkAddr = c.Flags.Uint64("forkaddr", 0, "wait until this address to fork and begin fuzzing")
		fuzzInterp = c.Flags.Bool("fuzzinterp", false, "controls whether fuzzing is delayed until program's main entry point")
		return nil
	}
	c.RunUsercorn = func() error {
		var err error
		u := c.Usercorn
		defer func() {
			if r := recover(); r != nil {
				u.Println("caught panic", r)
				u.Println(string(debug.Stack()))
			}
		}()

		aflState := C.afl_uc_hook(unsafe.Pointer(u.Backend().(uc.Unicorn).Handle()), aflArea, C.uint64_t(MAP_SIZE))
		if aflState == nil {
			panic("failed to setup hooks")
		}
		if nofork {
			status := 0
			err = u.Run()
			if _, ok := err.(models.ExitStatus); ok {
			} else if err != nil {
				u.Printf("Usercorn err: %s\n", err)
				status = 257
			}
			os.Exit(status)
		}

		// save cpu and memory state
		savedCtx, err := models.ContextSave(u)
		if err != nil {
			u.Println("context save failed.")
			return err
		}

		if _, err := forksrvStatus.Write(aflHello); err != nil {
			u.Println("AFL hello failed.")
			return errors.Wrap(err, "AFL hello failed.")
		}
		child := FakeProc{Argv: []string{"/bin/cat"}, Usercorn: u}
		var aflMsg [4]byte
		// afl forkserver loop
		u.Println("starting forkserver")
		for {
			if _, err := forksrvCtrl.Read(aflMsg[:]); err != nil {
				u.Printf("Failed to receive control signal from AFL: %s\n", err)
				return errors.Wrapf(err, "Failed to receive control signal from AFL: %s", err)
			}

			// spawn a fake child so AFL has something other than us to kill
			// monitor it and if afl kills it, stop the current emulation

			if err := child.Start(); err != nil {
				return err
			}
			// restore cpu and memory state
			if err := models.ContextRestore(u, savedCtx); err != nil {
				u.Println("context restore failed.")
				return err
			}

			binary.LittleEndian.PutUint32(aflMsg[:], uint32(child.Process.Pid))
			if _, err := forksrvStatus.Write(aflMsg[:]); err != nil {
				u.Printf("Failed to send pid to AFL: %s\n", err)
				return errors.Wrap(err, "failed to send PID to AFL")
			}

			status := 0
			err = u.Run()
			if _, ok := err.(models.ExitStatus); ok {
			} else if err != nil {
				u.Printf("Usercorn err: %s\n", err)
				status = 257
			}
			binary.LittleEndian.PutUint32(aflMsg[:], uint32(status))
			if _, err := forksrvStatus.Write(aflMsg[:]); err != nil {
				u.Printf("Failed to send status to AFL: %s\n", err)
				return errors.Wrap(err, "failed to send status to AFL")
			}
		}
	}
	os.Exit(c.Run(args, os.Environ()))
}

func init() { cmd.Register("fuzz", "fuzz acts as an AFL fork server", Main) }
