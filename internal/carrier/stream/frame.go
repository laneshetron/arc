// Package stream is the TLS/TCP carrier (spec §16.3): ARC packets carried
// over a TLS 1.3 byte stream, each prefixed by its length (§12.2). It is
// for networks that block or degrade UDP. TCP retransmits underneath the
// tunnel, so flows inside it see head-of-line blocking; sessions use these
// paths as fallbacks.
package stream

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/laneshetron/arc/internal/wire"
)

// ALPN is the TLS application protocol of the carrier.
const ALPN = "arc/1"

// Frame length bounds (§12.2): no ARC packet is shorter than a stateless
// reset or longer than the maximum packet size.
const (
	minFrame = wire.StatelessResetLen
	maxFrame = wire.MaxPacketSize
)

var errFrameLen = errors.New("stream: invalid frame length")

// appendFrame appends pkt with its length prefix.
func appendFrame(b, pkt []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(pkt)))
	return append(b, pkt...)
}

// frameReader reads length-prefixed packets from a stream.
type frameReader struct {
	r   *bufio.Reader
	hdr [2]byte
}

func newFrameReader(r io.Reader) *frameReader {
	return &frameReader{r: bufio.NewReaderSize(r, 64<<10)}
}

// next reads one packet into buf, which must hold maxFrame bytes, and
// returns its length. A malformed length is a fatal stream error: there is
// no way to resynchronize.
func (f *frameReader) next(buf []byte) (int, error) {
	if _, err := io.ReadFull(f.r, f.hdr[:]); err != nil {
		return 0, err
	}
	n := int(binary.BigEndian.Uint16(f.hdr[:]))
	if n < minFrame || n > maxFrame {
		return 0, fmt.Errorf("%w: %d", errFrameLen, n)
	}
	if _, err := io.ReadFull(f.r, buf[:n]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0, err
	}
	return n, nil
}

// buffered reports whether a complete frame is already buffered, so a
// reader can keep collecting frames into one batch without blocking.
func (f *frameReader) buffered() bool {
	if f.r.Buffered() < 2 {
		return false
	}
	h, _ := f.r.Peek(2)
	return f.r.Buffered() >= 2+int(binary.BigEndian.Uint16(h))
}
