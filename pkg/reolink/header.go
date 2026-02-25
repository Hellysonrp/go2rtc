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
	StreamType uint8  // stream_code in neolink (BcMeta.stream_type); not the XML Preview.handle
	MsgNum     uint16 // used to match replies to requests; camera echoes it back
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

// buildEncOffset builds the 4-byte value for wire bytes 12-15: [channel][streamType][msgNum LE] (neolink layout).
func buildEncOffset(channel, streamType uint8, msgNum uint16) uint32 {
	return uint32(channel) | uint32(streamType)<<8 | uint32(msgNum)<<16
}

func parseEncOffset(encOffset uint32) (channel, streamType uint8, msgNum uint16) {
	channel = uint8(encOffset)
	streamType = uint8(encOffset >> 8)
	msgNum = uint16(encOffset >> 16)
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
	channel, streamType, msgNum := parseEncOffset(h.EncOffset)
	h.Channel = channel
	h.Stream = 0
	h.StreamType = streamType
	h.MsgNum = msgNum
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
