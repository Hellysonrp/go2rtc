package reolink

import (
	"encoding/binary"
	"io"
)

// IDs
const (
	MagicLE uint32 = 0x0ABCDEF0 // appears on wire as f0 de bc 0a
	MagicBE uint32 = 0xF0DEBC0A // appears on wire as 0a bc de f0
)

// Message classes determine header layout
const (
	ClassLegacy20   uint16 = 0x6514 // 20-byte header: legacy login/upgrade
	ClassModern20   uint16 = 0x6614 // 20-byte header: modern (no payload offset)
	ClassModern24   uint16 = 0x6414 // 24-byte header: modern (has payload offset)
	ClassModern24BE uint16 = 0x1464 // 24-byte header: big-endian class marker observed
	ClassModern00   uint16 = 0x0000 // 24-byte header: modern (alt)
)

// Header is a unified view over 20/24 byte headers
type Header struct {
	Magic      uint32
	MessageID  uint32
	BodyLength uint32
	Channel    uint8
	Stream     uint8
	StreamType uint8 // stream_code in neolink (BcMeta.stream_type); not the XML Preview.handle
	Status     uint16
	Class      uint16

	// Derived/transport fields; not serialized. Populated during read/write.
	EncOffset     uint32
	PayloadOffset uint32
	Is24          bool
}

func writeHeader(w io.Writer, h Header) (n int, err error) {
	var hdr []byte

	switch h.Class {
	case ClassLegacy20, ClassModern20: // 20-byte header
		hdr = make([]byte, 20)
		binary.LittleEndian.PutUint32(hdr[0:4], h.Magic)

		binary.LittleEndian.PutUint32(hdr[4:8], h.MessageID)
		binary.LittleEndian.PutUint32(hdr[8:12], h.BodyLength)
		binary.LittleEndian.PutUint32(hdr[12:16], h.EncOffset)
		binary.LittleEndian.PutUint16(hdr[16:18], h.Status)
		binary.LittleEndian.PutUint16(hdr[18:20], h.Class)
	case ClassModern24, ClassModern00, ClassModern24BE: // 24-byte header
		hdr = make([]byte, 24)
		binary.LittleEndian.PutUint32(hdr[0:4], h.Magic)

		binary.LittleEndian.PutUint32(hdr[4:8], h.MessageID)
		binary.LittleEndian.PutUint32(hdr[8:12], h.BodyLength)
		binary.LittleEndian.PutUint32(hdr[12:16], h.EncOffset)
		binary.LittleEndian.PutUint16(hdr[16:18], h.Status)
		binary.LittleEndian.PutUint16(hdr[18:20], h.Class)
		binary.LittleEndian.PutUint32(hdr[20:24], h.PayloadOffset)
	}

	return w.Write(hdr)
}

func buildEncOffset(channel, stream, streamType uint8) uint32 {
	// EncOffset layout (little-endian bytes on wire): [channel][stream][0x00][streamType]; streamType = stream_code in neolink
	return uint32(channel) | uint32(stream)<<8 | 0<<16 | uint32(streamType)<<24
}

func parseEncOffset(encOffset uint32) (channel, stream, streamType uint8) {
	channel = uint8(encOffset)
	stream = uint8(encOffset >> 8)
	streamType = uint8(encOffset >> 24)
	return
}

func parseHeader(r io.Reader) (Header, error) {
	var h Header

	buf := make([]byte, 20)
	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return h, err
	}
	h.Magic = binary.LittleEndian.Uint32(buf[0:4])
	h.MessageID = binary.LittleEndian.Uint32(buf[4:8])
	h.BodyLength = binary.LittleEndian.Uint32(buf[8:12])
	h.EncOffset = binary.LittleEndian.Uint32(buf[12:16])
	channel, stream, streamType := parseEncOffset(h.EncOffset)
	h.Channel = channel
	h.Stream = stream
	h.StreamType = streamType
	h.Status = binary.LittleEndian.Uint16(buf[16:18])
	h.Class = binary.LittleEndian.Uint16(buf[18:20])

	switch h.Class {
	case ClassModern00, ClassModern24:
		po := make([]byte, 4)
		if err := binary.Read(r, binary.LittleEndian, &po); err != nil {
			return h, err
		}
		val := binary.LittleEndian.Uint32(po)
		h.PayloadOffset = val
		h.Is24 = true
	}

	return h, nil
}
