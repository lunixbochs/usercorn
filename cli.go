package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <exe> [args...]\n", os.Args[0])
		os.Exit(1)
	}
	corn, err := NewUsercorn(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	err = corn.Run(os.Args[1:]...)
	if err != nil {
		log.Fatal(err)
	}
}
