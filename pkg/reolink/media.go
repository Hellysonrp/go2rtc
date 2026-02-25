package reolink

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
)

var ErrInvalidPayloadSize = errors.New("invalid payload size")

func parseIFrame(payload []byte) ([]byte, uint32, uint32, string, error) {
	buf := bytes.NewBuffer(payload)
	_ = buf.Next(4)
	codec := string(buf.Next(4))
	payloadSize := binary.LittleEndian.Uint32(buf.Next(4))
	additionalHeader := binary.LittleEndian.Uint32(buf.Next(4))
	ms := binary.LittleEndian.Uint32(buf.Next(4))
	_ = binary.LittleEndian.Uint32(buf.Next(4))
	var time uint32
	if additionalHeader >= 4 {
		time = binary.LittleEndian.Uint32(buf.Next(4))
	}
	if additionalHeader > 4 {
		remainder := additionalHeader - 4
		_ = buf.Next(int(remainder))
	}

	data := buf.Next(int(payloadSize))
	if len(data) != int(payloadSize) {
		return nil, 0, 0, "", ErrInvalidPayloadSize
	}

	return data, ms, time, codec, nil
}

func parsePFrame(payload []byte) ([]byte, uint32, string, error) {
	buf := bytes.NewBuffer(payload)
	_ = buf.Next(4)
	codec := string(buf.Next(4))
	payloadSize := binary.LittleEndian.Uint32(buf.Next(4))
	additionalHeader := binary.LittleEndian.Uint32(buf.Next(4))
	ms := binary.LittleEndian.Uint32(buf.Next(4))                   // microseconds
	_ = binary.LittleEndian.Uint32(buf.Next(4))                     // unknown
	_ = binary.LittleEndian.Uint32(buf.Next(int(additionalHeader))) //additional header

	data := buf.Next(int(payloadSize))
	if len(data) != int(payloadSize) {
		return nil, 0, "", ErrInvalidPayloadSize
	}

	return data, ms, codec, nil
}

func parseAACFrame(payload []byte) ([]byte, error) {
	buf := bytes.NewBuffer(payload)
	_ = buf.Next(4)
	payloadSize := binary.LittleEndian.Uint16(buf.Next(2))
	_ = binary.LittleEndian.Uint16(buf.Next(2))
	data := buf.Next(int(payloadSize))
	if len(data) != int(payloadSize) {
		return nil, ErrInvalidPayloadSize
	}

	return data, nil
}

type InfoV2 struct {
	Width       uint32
	Height      uint32
	FPS         uint8
	StartYear   uint16
	StartMonth  uint8
	StartDate   uint8
	StartHour   uint8
	StartMinute uint8
	StartSecond uint8
	EndYear     uint16
	EndMonth    uint8
	EndDate     uint8
	EndHour     uint8
	EndMinute   uint8
	EndSecond   uint8
}

func parseInfoV2(payload []byte) *InfoV2 {
	buf := bytes.NewBuffer(payload)
	info := &InfoV2{}
	_ = buf.Next(4) //magic
	_ = buf.Next(4) //data size
	info.Width = binary.LittleEndian.Uint32(buf.Next(4))
	info.Height = binary.LittleEndian.Uint32(buf.Next(4))
	_ = buf.Next(1)
	info.FPS = uint8(buf.Next(1)[0])
	info.StartYear = uint16(buf.Next(1)[0]) + 1900
	info.StartMonth = uint8(buf.Next(1)[0])
	info.StartDate = uint8(buf.Next(1)[0])
	info.StartHour = uint8(buf.Next(1)[0])
	info.StartMinute = uint8(buf.Next(1)[0])
	info.StartSecond = uint8(buf.Next(1)[0])
	info.EndYear = uint16(buf.Next(1)[0]) + 1900
	info.EndMonth = uint8(buf.Next(1)[0])
	info.EndDate = uint8(buf.Next(1)[0])
	info.EndHour = uint8(buf.Next(1)[0])
	info.EndMinute = uint8(buf.Next(1)[0])
	info.EndSecond = uint8(buf.Next(1)[0])

	return info
}

type BCMediaPacket struct {
	Codec        string
	Data         []byte
	Microseconds uint32
	Timestamp    uint32
	info         *InfoV2
}

var (
	iFrameMagic = []byte{0x30, 0x30, 0x64, 0x63}
	pFrameMagic = []byte{0x30, 0x31, 0x64, 0x63}
	aacMagic    = []byte{0x30, 0x35, 0x77, 0x62}
	infoV2Magic = []byte{0x31, 0x30, 0x30, 0x32}
)

func NewBCMediaPacket(data []byte) (*BCMediaPacket, error) {
	magic := data[:4]
	var codec string
	var p []byte
	var ms uint32
	var timestamp uint32
	var err error
	switch {
	case bytes.Equal(magic, infoV2Magic):
		codec = "info"
		info := parseInfoV2(data)
		return &BCMediaPacket{
			Codec:        codec,
			Data:         data,
			Microseconds: ms,
			Timestamp:    timestamp,
			info:         info,
		}, nil

	case bytes.Equal(magic, iFrameMagic):
		p, ms, timestamp, codec, err = parseIFrame(data)

	case bytes.Equal(magic, pFrameMagic):
		p, ms, codec, err = parsePFrame(data)

	case bytes.Equal(magic, aacMagic):
		p, err = parseAACFrame(data)
		codec = "AAC"

	default:
		log.Printf("Warning: codec magic not supported: %x", magic)
		p = data
	}
	if err != nil {
		return nil, err
	}

	return &BCMediaPacket{
		Codec:        codec,
		Data:         p,
		Microseconds: ms,
		Timestamp:    timestamp,
		info:         nil,
	}, nil
}

// StreamParams returns streamCode, previewHandle, and streamType for a streamKind (for start/stop).
func StreamParams(streamKind string) (streamCode uint8, previewHandle uint32, streamType string) {
	switch streamKind {
	case "sub":
		return 1, 256, "subStream"
	case "extern":
		return 0, 1024, "externStream"
	default:
		return 0, 0, "mainStream"
	}
}

func (bc *BCConn) startStream(streamKind string, msgNum uint16) (*BCStreamReader, error) {
	streamCode, previewHandle, streamType := StreamParams(streamKind)

	hdr := Header{
		Magic:      MagicLE,
		MessageID:  3,
		Status:     0,
		StreamType: streamCode,
		Channel:    0,
		MsgNum:     msgNum,
		Class:      0x6414,
	}

	var startStreamReq StartStreamReq
	startStreamReq.Preview.ChannelId = "0"
	startStreamReq.Preview.Handle = fmt.Sprintf("%d", previewHandle)
	startStreamReq.Preview.StreamType = streamType
	xmlBodyBytes, err := xml.Marshal(startStreamReq)
	if err != nil {
		return nil, fmt.Errorf("marshal start stream request: %w", err)
	}

	err = bc.aesSend(hdr, nil, xmlBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("send start stream request: %w", err)
	}

	return &BCStreamReader{
		conn:               bc,
		expectedStreamType: streamCode,
	}, nil
}

// stopStream sends VIDEO_STOP (4) so the camera stops sending stream data. Fire-and-forget; call before closing.
func stopStream(bc *BCConn, streamCode uint8, previewHandle uint32, msgNum uint16) error {
	hdr := Header{
		Magic:      MagicLE,
		MessageID:  MsgIDVideoStop,
		Status:     0,
		StreamType: streamCode,
		Channel:    0,
		MsgNum:     msgNum,
		Class:      0x6414,
	}
	var stopReq StopStreamReq
	stopReq.Preview.Version = "1.1"
	stopReq.Preview.ChannelId = "0"
	stopReq.Preview.Handle = fmt.Sprintf("%d", previewHandle)
	xmlBodyBytes, err := xml.Marshal(stopReq)
	if err != nil {
		return fmt.Errorf("marshal stop stream request: %w", err)
	}
	return bc.aesSend(hdr, nil, xmlBodyBytes)
}

type BCStreamReader struct {
	conn               *BCConn
	expectedStreamType uint8
}

func (r *BCStreamReader) Next() (*BCMediaPacket, error) {
	var current *[]byte

	for {
		msg, err := r.conn.readHeaderAndBody()
		if err != nil {
			return nil, err
		}
		h := msg.header
		resp := msg.body
		if h.MessageID == MsgIDKeepalive {
			_ = r.conn.SendKeepaliveReply(h)
			continue
		}
		if h.Status != 200 {
			continue
		}
		if h.MessageID != 3 {
			continue
		}
		if h.StreamType != r.expectedStreamType {
			continue
		}

		extLen := h.PayloadOffset
		if extLen > uint32(len(resp)) || h.BodyLength > uint32(len(resp)) {
			return nil, fmt.Errorf("invalid message bounds")
		}
		extBytes := resp[:extLen]
		payloadBytes := resp[extLen:h.BodyLength]

		ext := decryptAES(r.conn.aesKey, extBytes)
		var extension Extension

		err = xml.Unmarshal(ext, &extension)
		if err != nil {
			return nil, fmt.Errorf("unmarshal extension: %w", err)
		}

		var decryptedPayload []byte
		if extension.EncryptLen != 0 {
			decryptedPayload = decryptAES(r.conn.aesKey, payloadBytes)[:extension.EncryptLen]
		} else {
			decryptedPayload = payloadBytes
		}

		if extension.BinaryData == 1 {
			p, err := NewBCMediaPacket(decryptedPayload)
			// Theres more packets incoming
			// Reset current, and set current to the segment
			if err == ErrInvalidPayloadSize {
				current = nil
				current = &decryptedPayload

				// Something else went wrong
				// Reset current, skip the packet, and continue
			} else if err != nil {
				current = nil
				continue

				// Whole packet is contained by this segment
				// Return the packet
			} else {
				return p, nil
			}
		} else {
			// if current is nil, there was no binarydata=1 packet
			// before this, therefore nothing to append to, therefore
			// drop and continue
			if current == nil {
				continue
			}
			// otherwise append decryptedPayload to current
			*current = append(*current, decryptedPayload...)

			// try and parse
			p, err := NewBCMediaPacket(*current)

			// If it's still not the right size, then continue
			if err == ErrInvalidPayloadSize {
				continue

				// Something else has gone wrong, so clear current and continue
			} else if err != nil {
				current = nil
				continue
			}

			// Finally, return the packet
			return p, nil
		}

	}
}
