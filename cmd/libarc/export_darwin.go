package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef int (*arc_event_fn)(void *context, const char *event_json);

static int arc_call(arc_event_fn fn, void *context, const char *event_json) {
	return fn(context, event_json);
}
*/
import "C"

import (
	"syscall"
	"unsafe"

	"github.com/laneshetron/arc/internal/client"
	"github.com/laneshetron/arc/internal/tun"
)

var tunnels registry

//export arc_start
func arc_start(configJSON *C.char, tunFD C.int, callback C.arc_event_fn, context unsafe.Pointer, handle *C.int64_t) *C.char {
	if configJSON == nil || callback == nil || handle == nil {
		if tunFD >= 0 {
			syscall.Close(int(tunFD)) // arc.h: closed on any failure
		}
		return C.CString("arc_start: config_json, callback and handle must not be NULL")
	}
	cfg := C.GoString(configJSON)
	dev, err := tun.FromFD(int(tunFD))
	if err != nil {
		return C.CString("tun_fd: " + err.Error())
	}
	t, err := start([]byte(cfg), dev, func(event []byte) int {
		s := C.CString(string(event))
		defer C.free(unsafe.Pointer(s))
		return int(C.arc_call(callback, context, s))
	})
	if err != nil {
		return C.CString(err.Error())
	}
	*handle = C.int64_t(tunnels.add(t))
	t.begin()
	return nil
}

//export arc_stop
func arc_stop(handle C.int64_t) {
	tunnels.stop(int64(handle))
}

//export arc_generate_key
func arc_generate_key() *C.char {
	b, err := generateKey()
	if err != nil {
		return nil
	}
	return C.CString(string(b))
}

//export arc_version
func arc_version() *C.char { return C.CString(client.Version()) }

//export arc_free
func arc_free(s *C.char) { C.free(unsafe.Pointer(s)) }
