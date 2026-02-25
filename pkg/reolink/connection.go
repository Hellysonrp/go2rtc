package reolink

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	EncReqAESCam = 0xDC12 // 0xDC12 -> bytes [encrypt=0x12][unknown=0xDC]
	maxBodySize  = 1 << 20
)

func NewBCConn(cameraIP, port, username, password string) (*BCConn, error) {
	conn, err := net.Dial("tcp", cameraIP+":"+port)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	self := &BCConn{
		conn:   conn,
		reader: NewMessageReader(conn),
	}

	_, err = self.login(username, password)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("login: %w", err)
	}

	return self, nil
}

type BCConn struct {
	conn            net.Conn
	reader          *MessageReader
	username        string
	password        string
	nonce           string
	aesKey          []byte
	messageCount    uint32
	isAuthenticated bool
}

func (bc *BCConn) Close() error {
	return bc.conn.Close()
}

type BCMsg struct {
	header Header
	body   []byte
}

type MessageReader struct {
	r io.Reader
}

func NewMessageReader(r io.Reader) *MessageReader {
	return &MessageReader{r: r}
}

func (mr *MessageReader) Next() (BCMsg, error) {
	h, err := parseHeader(mr.r)
	if err != nil {
		return BCMsg{}, fmt.Errorf("parse header failed: %v", err)
	}
	if h.BodyLength > maxBodySize {
		return BCMsg{}, fmt.Errorf("body length %d exceeds maximum (wrong port or non-Baichuan response?)", h.BodyLength)
	}
	var body []byte
	if h.BodyLength > 0 {
		body = make([]byte, h.BodyLength)
		if _, err := io.ReadFull(mr.r, body); err != nil {
			return BCMsg{}, fmt.Errorf("read body: %w", err)
		}
	}
	return BCMsg{header: h, body: body}, nil
}

func (bc *BCConn) bcSend(header Header, extension []byte, body []byte, bcEncrypt bool) error {
	header.EncOffset = buildEncOffset(header.Channel, 0, header.StreamType)
	if len(extension) > 0 {
		header.PayloadOffset = uint32(len(extension))
	}

	if bcEncrypt {
		body = encryptBC(header.EncOffset, body)
		extBody := encryptBC(header.EncOffset, extension)
		body = append(extBody, body...)
	}
	header.BodyLength = uint32(len(body))

	_, err := writeHeader(bc.conn, header)
	if err != nil {
		return fmt.Errorf("write header failed: %v", err)
	}
	if _, err := bc.conn.Write(body); err != nil {
		return fmt.Errorf("write body failed: %v", err)
	}
	return nil
}

func (bc *BCConn) readHeaderAndBody() (BCMsg, error) {
	if bc.reader == nil {
		bc.reader = NewMessageReader(bc.conn)
	}
	return bc.reader.Next()
}

func (bc *BCConn) login(username, password string) (ModernLoginRes, error) {
	bc.username = username
	bc.password = password

	// 1) Legacy upgrade to obtain nonce (request AES)
	var header Header
	header.Magic = MagicLE
	header.MessageID = 1
	header.Status = EncReqAESCam
	header.StreamType = 1
	header.Class = ClassLegacy20

	err := bc.bcSend(header, nil, nil, false)
	if err != nil {
		return ModernLoginRes{}, fmt.Errorf("send legacy upgrade failed: %w", err)
	}
	msg, err := bc.readHeaderAndBody()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return ModernLoginRes{}, fmt.Errorf("read legacy reply (AES) failed: %w (wrong port? Reolink Baichuan uses port 9000)", err)
		}
		return ModernLoginRes{}, fmt.Errorf("read legacy reply (AES) failed: %w", err)
	}
	if msg.header.Magic != MagicLE && msg.header.Magic != MagicBE {
		return ModernLoginRes{}, fmt.Errorf("invalid legacy reply: magic 0x%08x (is the correct port configured? Reolink Baichuan uses port 9000, not RTSP 554)", msg.header.Magic)
	}
	h := msg.header
	body := msg.body

	var resp LegacyLoginRes

	dec := decryptBC(h.EncOffset, body)
	err = xml.Unmarshal(dec, &resp)
	if err != nil {
		return ModernLoginRes{}, fmt.Errorf("failed to unmarshal legacy response: %w", err)
	}
	nonce := resp.Encryption.Nonce
	if nonce == "" {
		return ModernLoginRes{}, fmt.Errorf("failed to obtain nonce; header status=0x%04x", h.Status)
	}
	bc.nonce = nonce

	keyString := md5HexUpper([]byte(fmt.Sprintf("%s-%s", bc.nonce, bc.password)))[:16]
	bc.aesKey = []byte(keyString)

	// 2) Modern login: MD5(username+nonce), MD5(password+nonce) (lowercase hex)
	userHash := md5HexUpper([]byte(username + nonce))
	passHash := md5HexUpper([]byte(password + nonce))

	b := NewModernLoginReq(userHash, passHash)

	xmlBody := []byte(xml.Header + string(b))

	header.Magic = MagicLE
	header.MessageID = 1
	header.Status = 0
	header.StreamType = 1
	header.Class = ClassModern24

	err = bc.bcSend(header, nil, xmlBody, true)
	if err != nil {
		return ModernLoginRes{}, fmt.Errorf("send modern login failed: %w", err)
	}

	msg, err = bc.readHeaderAndBody()
	if err != nil {
		return ModernLoginRes{}, fmt.Errorf("read modern login reply failed: %w", err)
	}
	h2 := msg.header
	body2 := msg.body
	dec = decryptBC(h2.EncOffset, body2)
	var modernLoginRes ModernLoginRes
	err = xml.Unmarshal(dec, &modernLoginRes)
	if err != nil {
		return ModernLoginRes{}, fmt.Errorf("failed to unmarshal modern response: %w", err)
	}

	return modernLoginRes, nil
}

func (bc *BCConn) aesSend(header Header, extension []byte, body []byte) error {
	header.EncOffset = buildEncOffset(header.Channel, 0, header.StreamType)
	if len(extension) > 0 {
		header.PayloadOffset = uint32(len(extension))
	}

	body = encryptAES(bc.aesKey, body)
	extBody := encryptAES(bc.aesKey, extension)
	body = append(extBody, body...)

	header.BodyLength = uint32(len(body))

	_, err := writeHeader(bc.conn, header)
	if err != nil {
		return fmt.Errorf("write header failed: %v", err)
	}
	if _, err := bc.conn.Write(body); err != nil {
		return fmt.Errorf("write body failed: %v", err)
	}
	return nil

}
