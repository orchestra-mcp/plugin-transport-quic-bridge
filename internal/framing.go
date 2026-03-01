package internal

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// maxMessageSize is the maximum allowed size for a single framed JSON message
// (16 MB), matching the protobuf framing limit.
const maxMessageSize = 16 * 1024 * 1024

// writeJSONFrame serializes v as JSON and writes it to w using length-delimited
// framing: [4 bytes big-endian uint32 length][N bytes JSON payload].
func writeJSONFrame(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	if len(data) > maxMessageSize {
		return fmt.Errorf("message size %d exceeds maximum %d", len(data), maxMessageSize)
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// readJSONFrame reads a length-delimited JSON message from r and unmarshals it
// into v. The framing format must match writeJSONFrame.
func readJSONFrame(r io.Reader, v any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > maxMessageSize {
		return fmt.Errorf("message size %d exceeds maximum %d", size, maxMessageSize)
	}
	if size == 0 {
		return fmt.Errorf("empty message")
	}

	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return fmt.Errorf("read payload: %w", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("unmarshal JSON: %w", err)
	}
	return nil
}
