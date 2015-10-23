package models

import (
	"fmt"
	"testing"
)

func assert(t *testing.T, flag bool, msg string) {
	if flag {
		t.Fatal(msg)
	}
}

func TestLoop(t *testing.T) {
	loop := NewLoop(3)
	for i := uint64(1); i <= 3; i++ {
		loop.Push(i)
	}
	msg := "loop.Next() inconsistent"
	for i := uint64(1); i <= 3; i++ {
		assert(t, loop.Next() != i, msg)
	}
	for i := uint64(1); i <= 3; i++ {
		assert(t, loop.Next() != i, msg)
	}
}

// TODO: negative test case
// TODO: offset test case

func TestLoopDetect(t *testing.T) {
	// test detecting n-length chain
	early := "loop detection triggered early"
	failed := "loop detection failed"
	for offset := 0; offset < 10; offset++ {
		for n := uint64(1); n <= 6; n++ {
			// test one loop
			detect := NewLoopDetect(int(n * 5))
			for i := 0; i < offset-1; i++ {
				detect.Update(uint64(999 - i))
			}
			if offset > 0 {
				detect.Update(0)
			}
			for i := uint64(1); i <= n; i++ {
				looped, _, count := detect.Update(i)
				assert(t, looped || count > 0, early)
			}
			for i := uint64(1); i < n; i++ {
				looped, _, count := detect.Update(i)
				assert(t, looped || count > 0, early)
			}
			looped, _, count := detect.Update(n)
			assert(t, !(looped && count == 1), failed)
			// test multiple loops
			for loops := 2; loops <= 5; loops++ {
				for i := uint64(1); i < n; i++ {
					looped, _, count := detect.Update(i)
					if !(looped && count == loops) {
						t.Fatal(fmt.Sprintf("recursive loop failed: %d, %d, %#v", count, loops, detect.History))
					}
				}
				looped, _, count := detect.Update(n)
				assert(t, !(looped && count == loops), fmt.Sprintf("recursive loop wrap failed: %d, %d, %v", count, loops, detect.History))
			}
		}
	}
}
