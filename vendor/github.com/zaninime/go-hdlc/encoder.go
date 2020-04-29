package hdlc

import (
	"bufio"
	"encoding/binary"
	"io"

	"github.com/sigurn/crc16"
)

// An Encoder writes HDLC frames to an output stream.
type Encoder struct {
	w    io.Writer
	bufW *bufio.Writer
}

// NewEncoder returns a new encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		w:    w,
		bufW: bufio.NewWriter(w),
	}
}

// WriteFrame writes the frame f on the output stream, encoding it's content.
func (e Encoder) WriteFrame(f *Frame) (int, error) {
	var err error

	var n, nn int
	if err = e.bufW.WriteByte(flagSym); err != nil {
		return 0, err
	}
	n++
	if f.HasAddressCtrlPrefix {
		if nn, err = writeEscapedData(addressCtrlSeq, e.bufW); err != nil {
			return n + nn, err
		}
		n += nn
	}
	if nn, err = writeEscapedData(f.Payload, e.bufW); err != nil {
		return n + nn, err
	}
	n += nn
	if nn, err = writeEscapedData(f.FCS, e.bufW); err != nil {
		return n + nn, err
	}
	n += nn
	if err = e.bufW.WriteByte(flagSym); err != nil {
		return n + 1, err
	}
	n++

	if err = e.bufW.Flush(); err != nil {
		return n, err
	}

	return n, nil
}

func writeEscapedData(p []byte, out *bufio.Writer) (int, error) {
	var err error
	written := 0

	for i, b := range p {
		if (b) < 0x20 || ((b)&0x7f) == 0x7d || ((b)&0x7f) == 0x7e {
			if err = out.WriteByte(escapeSym); err != nil {
				return written, err
			}
			if err = out.WriteByte(b ^ 0x20); err != nil {
				return written, err
			}
		} else {
			if err = out.WriteByte(b); err != nil {
				return written, err
			}
		}

		written = i
	}

	return written + 1, nil
}

// Encapsulate takes a payload p and some configuration and creates a frame that
// can be written with an Encoder.
func Encapsulate(p []byte, hasAddressCtrlPrefix bool) *Frame {
	crc := crc16.Init(crcTable)

	if hasAddressCtrlPrefix {
		crc = crc16.Update(crc, addressCtrlSeq, crcTable)
	}

	crc = crc16.Update(crc, p, crcTable)
	crc = crc16.Complete(crc, crcTable)
	crc ^= 0xffff
	crcBytes := []byte{0, 0}
	binary.LittleEndian.PutUint16(crcBytes, crc)

	return &Frame{
		Payload:              p,
		FCS:                  crcBytes,
		HasAddressCtrlPrefix: hasAddressCtrlPrefix,
	}
}
