package applepay

// This file is a simple interface to OpenSSL's BIO structures. It provides an
// API similar to bytes.Buffer's. It is not segregated in a separate package
// because of cgo concerns (i.e. not being able to pass C types across
// packages)

/*
#cgo CFLAGS: -I/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/ -I/usr/local/opt/openssl/include
#cgo LDFLAGS: -L/usr/local/opt/openssl/lib
#cgo pkg-config: openssl
#include <openssl/x509v3.h>
*/
import "C"

import (
	"io"
	"io/ioutil"
	"unsafe"
)

type bio C.struct_bio_st

// newBIO returns an empty in-memory BIO
func newBIO() *bio {
	b := C.BIO_new(C.BIO_s_mem())
	return (*bio)(b)
}

// newBIOBytes creates a new BIO from an existing byte buffer
func newBIOBytes(buf []byte) *bio {
	b := C.BIO_new_mem_buf(C.CBytes(buf), C.int(len(buf)))
	return (*bio)(b)
}

// Free frees BIO's memory
func (b *bio) Free() {
	C.BIO_free_all(b.C())
}

// Read implements io.Reader for BIO
func (b *bio) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n = int(C.BIO_read((*C.BIO)(b), unsafe.Pointer(&buf[0]), C.int(len(buf))))
	if n <= 0 {
		return 0, io.EOF
	}
	return n, nil
}

// ReadAll returns the bytes stored in a BIO
func (b *bio) ReadAll() []byte {
	bytes, _ := ioutil.ReadAll(b)
	return bytes
}

// ReadAllString returns the data stored in BIO under the form of a string
func (b *bio) ReadAllString() string {
	return string(b.ReadAll())
}

// C returns the C form of a BIO (useful for cgo calls)
func (b *bio) C() *C.struct_bio_st {
	return (*C.struct_bio_st)(b)
}
