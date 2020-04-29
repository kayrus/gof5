package hdlc

import "errors"

var (
	// ErrInvalidFrame represents any decoding error where the data received
	// doesn't respect the HDLC spec.
	ErrInvalidFrame = errors.New("invalid frame")

	// ErrEmptyFrame is returned every time there's an empty frame on the stream,
	// ie. when decoding.
	ErrEmptyFrame = errors.New("empty frame")
)
