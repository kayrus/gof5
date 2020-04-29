package hdlc

import (
	"bufio"
	"bytes"
	"io"
)

// A Decoder reads HDLC frames from an input stream.
type Decoder struct {
	bufReader  *bufio.Reader
	inSync     bool
	decoderBuf bytes.Buffer
}

// NewDecoder returns a new decoder that reads from r.
// The decoder introduces its own buffering and may read data from r beyond the requested frames.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		bufReader: bufio.NewReader(r),
		inSync:    false,
	}
}

// ReadFrame re-syncs the Decoder if necessary and reads the next frame.
// Returns ErrInvalidFrame if the decoding fails. Returns ErrEmptyFrame when the
// frame has no content to decode.
func (fd *Decoder) ReadFrame() (*Frame, error) {
	var err error
	frame := Frame{}
	if !fd.inSync {
		if err := fd.resync(); err != nil {
			return nil, err
		}
		fd.inSync = true
	}

	content, err := fd.readFrame()
	if err != nil {
		return nil, err
	}

	if len(content) == 0 {
		return nil, ErrEmptyFrame
	}

	decodedContentBuf := &fd.decoderBuf
	decodedContentBuf.Reset()

	inEscape := false
	for _, b := range content {
		if b == escapeSym {
			if inEscape {
				return nil, ErrInvalidFrame
			}

			inEscape = true
		} else if inEscape {
			decodedContentBuf.WriteByte(b ^ 0x20)
			inEscape = false
		} else if b < 0x20 {
			// skip byte introduced by DCE
		} else {
			decodedContentBuf.WriteByte(b)
		}
	}

	if inEscape || decodedContentBuf.Len() < 3 {
		return nil, ErrInvalidFrame
	}

	decodedContent := decodedContentBuf.Bytes()
	decodedContentNoFCS := decodedContent[:len(decodedContent)-2]
	frame.FCS = decodedContent[len(decodedContent)-2:]

	if bytes.Equal(decodedContent[0:len(addressCtrlSeq)], addressCtrlSeq) {
		frame.HasAddressCtrlPrefix = true
		frame.Payload = decodedContentNoFCS[len(addressCtrlSeq):]
	} else {
		frame.Payload = decodedContentNoFCS
	}

	return &frame, nil
}

func (fd Decoder) readFrame() ([]byte, error) {
	frame, err := fd.bufReader.ReadBytes(flagSym)

	if err != nil {
		return nil, err
	}

	return frame[:len(frame)-1], err
}

func (fd Decoder) resync() error {
	for {
		_, err := fd.bufReader.ReadBytes(flagSym)

		if err != nil {
			return err
		}

		peek1, err := fd.bufReader.Peek(1)
		if err != nil {
			return err
		}

		if peek1[0] != flagSym {
			break
		}
	}

	return nil
}
