package hdlc

import (
	"github.com/sigurn/crc16"
)

const (
	flagSym   byte = 0x7e
	escapeSym byte = 0x7d
	abortSym  byte = 0x7f
)

var (
	addressCtrlSeq        = []byte{0xff, 0x03}
	crcTable              = crc16.MakeTable(crc16.CRC16_MCRF4XX)
	crcGood        uint16 = 0xf0b8
)

// A Frame is an HDLC frame.
// Use Encapsulate to create a new one starting from a payload.
type Frame struct {
	Payload              []byte
	FCS                  []byte
	HasAddressCtrlPrefix bool
}

// Valid performs a CRC on the frame, based on the FCS and the other fields.
func (f Frame) Valid() bool {
	crc := crc16.Init(crcTable)
	if f.HasAddressCtrlPrefix {
		crc = crc16.Update(crc, addressCtrlSeq, crcTable)
	}
	crc = crc16.Update(crc, f.Payload, crcTable)
	crc = crc16.Update(crc, f.FCS, crcTable)
	return crc16.Complete(crc, crcTable) == crcGood
}
