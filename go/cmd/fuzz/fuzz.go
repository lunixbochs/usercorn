package main

import (
	"encoding/binary"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io/ioutil"
	"os"
	"unsafe"

	"github.com/lunixbochs/usercorn/go"
	"github.com/lunixbochs/usercorn/go/cmd"
	"github.com/lunixbochs/usercorn/go/models"
)

/*
#include <stdlib.h>
#include <sys/shm.h>
#include <string.h>

void *afl_setup() {
	char *id = getenv("__AFL_SHM_ID");
	if (id == NULL) {
		return NULL;
	}
	void *afl_area = shmat(atoi(id), NULL, 0);
	if (afl_area == (void *)-1) {
		return NULL;
	}
	memset(afl_area, 1, 1 << 16);
	return afl_area;
}

*/
import "C"

var MAP_SIZE uint64 = 1 << 16
var FORKSRV_FD = 198
var aflHello = []byte{1, 2, 3, 4}

func main() {
	message := []byte("In fuzz main")
	ioutil.WriteFile("/tmp/outfile", message, 0444)

	forksrvCtrl := os.NewFile(uintptr(FORKSRV_FD), "afl_ctrl")
	forksrvStatus := os.NewFile(uintptr(FORKSRV_FD+1), "afl_status")

	c := cmd.NewUsercornCmd()
	var forkAddr *uint64
	var fuzzInterp *bool

	aflArea := C.afl_setup()
	if aflArea == nil {
		panic("could not set up AFL shared memory")
	}
	fuzzMap := []byte((*[1 << 30]byte)(unsafe.Pointer(aflArea))[:])

	// Set one bit to true to go through successful count_bytes
	fuzzMap[1] = 1

	var lastPos uint64
	blockTrace := func(_ uc.Unicorn, addr uint64, size uint32) {
		if lastPos == 0 {
			lastPos = addr >> 1
			return
		}
		loc := (addr >> 4) ^ (addr << 8)
		loc &= MAP_SIZE - 1
		fuzzMap[loc]++
		lastPos = addr >> 1
	}
	c.SetupFlags = func() error {
		forkAddr = c.Flags.Uint64("forkaddr", 0, "wait until this address to fork and begin fuzzing")
		fuzzInterp = c.Flags.Bool("fuzzinterp", false, "controls whether fuzzing is delayed until program's main entry point")
		return nil
	}
	c.RunUsercorn = func(args, env []string) error {
		u := c.Usercorn
		u.Println("Starting Usercorn")
		if _, err := forksrvStatus.Write(aflHello); err != nil {
			u.Println("AFL hello failed.")
			return err
		}
		var aflMsg [4]byte
		// afl forkserver loop
		for {
			if _, err := forksrvCtrl.Read(aflMsg[:]); err != nil {
				u.Printf("Failed to receive control signal from AFL: %s\n", err)
				return err
			}
			u.Println("AFL requested new child")

			u.Println("Creating new Usercorn instance")
			tmp, err := usercorn.NewUsercorn(u.Exe(), u.Config())
			if err != nil {
				u.Printf("Usercorn creation failed: %s\n", err)
				return err
			}
			lastPos = 0
			if _, err := c.Usercorn.HookAdd(uc.HOOK_BLOCK, blockTrace, 1, 0); err != nil {
				u.Printf("Failed to add hook to tmp Usercorn: %s\n", err)
				return err
			}

			// spawn a fake child so AFL has something other than us to kill
			// monitor it and if afl kills it, stop the current emulation
			args := []string{"/bin/cat"}
			var procAttr os.ProcAttr
			proc, err := os.StartProcess(args[0], args, &procAttr)
			if err != nil {
				u.Printf("Failed to spawn child: %s\n", err)
				return err
			}
			u.Printf("Spawned child %v = %d\n", args, proc.Pid)

			binary.LittleEndian.PutUint32(aflMsg[:], uint32(proc.Pid))
			if _, err := forksrvStatus.Write(aflMsg[:]); err != nil {
				u.Printf("Failed to send pid to AFL: %s\n", err)
				return err
			}
			u.Println("Sent child pid to AFL")

			// Goroutine to stop usercorn if afl-fuzz kills our fake process
			go func() {
				proc.Wait()
				u.Stop()
				u.Println("Child+Usercorn stopped")
			}()

			status := 0
			err = tmp.Run(args, env)
			if _, ok := err.(models.ExitStatus); ok {
			} else if err != nil {
				u.Printf("Usercorn err: %s\n", err)
				status = 257
			}
			binary.LittleEndian.PutUint32(aflMsg[:], uint32(status))
			if _, err := forksrvStatus.Write(aflMsg[:]); err != nil {
				u.Printf("Failed to send status to AFL: %s\n", err)
				return err
			}

			proc.Kill()
			proc.Wait()
			u.Println("Fuzz loop ended")
		}
	}

	c.Run(os.Args, os.Environ())
}
