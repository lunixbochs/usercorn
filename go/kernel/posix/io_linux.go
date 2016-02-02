package posix

import (
	"fmt"
	"io/ioutil"
)

func PathFromFd(dirfd int) (string, error) {
	p, err := ioutil.ReadFile(fmt.Sprintf("/proc/self/fd/%d", dirfd))
	return string(p), err
}
