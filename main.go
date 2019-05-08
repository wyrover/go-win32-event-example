package main

import (
	"bytes"
	"fmt"
	"os"
	"unsafe"

	"runtime"
	"strconv"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// createEvent creates a Windows event ACL'd to builtin administrator
// and local system. Can use docker-signal to signal the event.
func createEvent(event string) (windows.Handle, error) {
	ev, _ := windows.UTF16PtrFromString(event)
	sd, err := winio.SddlToSecurityDescriptor("D:P(A;;GA;;;BA)(A;;GA;;;SY)")
	if err != nil {
		return 0, errors.Wrapf(err, "failed to get security descriptor for event '%s'", event)
	}
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1
	sa.SecurityDescriptor = uintptr(unsafe.Pointer(&sd[0]))
	h, err := windows.CreateEvent(&sa, 0, 0, ev)
	if h == 0 || err != nil {
		return 0, errors.Wrapf(err, "failed to create event '%s'", event)
	}
	return h, nil
}

var (
	exitEvent windows.Handle
)

func Cleanup() {
	if exitEvent != 0 {
		windows.CloseHandle(exitEvent)
	}
}

func getGID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

func main() {

	fmt.Println("hello")
	var err error

	exitEventName := fmt.Sprintf("%x%08x", os.Getpid(), getGID())

	fmt.Println(exitEventName)

	exitEventName16, _ := windows.UTF16PtrFromString(exitEventName)

	exitEvent, err = windows.CreateEvent(nil, 1, 0, exitEventName16)
	if err != nil {
		return
	}

	windows.SetEvent(exitEvent)

	Cleanup()
}
