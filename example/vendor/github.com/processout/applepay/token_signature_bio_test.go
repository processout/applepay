package applepay

import (
	"io"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestNewBIO(t *testing.T) {
	b := newBIO()
	Convey("BIO is not nil", t, func() {
		So(b, ShouldNotBeNil)
	})
}

func TestNewBytesBIO(t *testing.T) {
	b := newBIOBytes([]byte("test"))

	Convey("BIO is not nil", t, func() {
		So(b, ShouldNotBeNil)
	})

	Convey("BIO contains the right value", t, func() {
		So(b.ReadAllString(), ShouldEqual, "test")
	})
}

func TestFreeBIO(t *testing.T) {
	b := newBIO()

	Convey("Free does not panic", t, func() {
		So(b.Free, ShouldNotPanic)
	})
}

func TestReadBIO(t *testing.T) {

	Convey("Read returns nothing for nil buffers", t, func() {
		b := newBIOBytes([]byte("test"))
		n, err := b.Read(nil)

		Convey("n is zero", func() {
			So(n, ShouldEqual, 0)
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})

	Convey("Read returns io.EOF when appropriate", t, func() {
		b := newBIOBytes([]byte(""))
		buf := make([]byte, 1)
		n, err := b.Read(buf)

		Convey("n is zero", func() {
			So(n, ShouldEqual, 0)
		})

		Convey("buf is untouched", func() {
			So(buf, ShouldResemble, []byte{0})
		})

		Convey("err is io.EOF", func() {
			So(err, ShouldEqual, io.EOF)
		})

	})

	Convey("Read reads to the buffer properly", t, func() {
		b := newBIOBytes([]byte("test"))
		buf := make([]byte, 4)
		n, err := b.Read(buf)

		Convey("n is the length of the buffer", func() {
			So(n, ShouldEqual, 4)
		})

		Convey("buf is the contents of the buffer", func() {
			So(buf, ShouldResemble, []byte("test"))
		})

		Convey("err is nil", func() {
			So(err, ShouldBeNil)
		})
	})
}

func TestReadAllBIO(t *testing.T) {
	b := newBIOBytes([]byte("test"))

	Convey("ReadAll returns the full buffer", t, func() {
		So(b.ReadAll(), ShouldResemble, []byte("test"))
	})
}

func TestReadAllStringBIO(t *testing.T) {
	b := newBIOBytes([]byte("test"))

	Convey("ReadAllString returns the full buffer as a string", t, func() {
		So(b.ReadAllString(), ShouldEqual, "test")
	})
}

func TestCBIO(t *testing.T) {
	b := newBIO()

	Convey("C is not nil", t, func() {
		So(b.C(), ShouldNotBeNil)
	})
}
