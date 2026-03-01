package reolink

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/AlexxIT/go2rtc/pkg/aac"
	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/h264"
	"github.com/AlexxIT/go2rtc/pkg/h264/annexb"
	"github.com/AlexxIT/go2rtc/pkg/h265"
	"github.com/pion/rtp"
)

type Producer struct {
	core.Connection

	bcConn       *BCConn
	streamReader *BCStreamReader
	streamKind   string
	streamMsgNum uint16 // msg_num used for start stream; needed for VIDEO_STOP in Stop()
}

func Dial(source string) (core.Producer, error) {
	// fmt.Println(source)
	sourceUrl, err := url.Parse(source)
	if err != nil {
		return nil, err
	}

	ip := sourceUrl.Hostname()
	port := sourceUrl.Port()
	if port == "" {
		port = "9000"
	}
	username := sourceUrl.User.Username()
	password, ok := sourceUrl.User.Password()
	if !ok {
		return nil, fmt.Errorf("password is required")
	}

	bcConn, err := NewBCConn(ip, port, username, password)
	if err != nil {
		return nil, err
	}

	streamKind := "main"
	if q := sourceUrl.Query().Get("stream"); q != "" {
		switch strings.ToLower(q) {
		case "sub":
			streamKind = "sub"
		case "extern":
			streamKind = "extern"
		default:
			streamKind = "main"
		}
	}

	prod := &Producer{
		Connection: core.Connection{
			ID:         core.NewID(),
			FormatName: "reolink",
			Protocol:   "tcp", // wss
			RemoteAddr: ip,
			Source:     source,
			URL:        ip,
			Transport:  bcConn,
		},
		bcConn:     bcConn,
		streamKind: streamKind,
	}
	if err = prod.probe(); err != nil {
		return nil, err
	}

	return prod, nil
}

func (p *Producer) Start() error {
	var video, video265 *core.Receiver

	for _, receiver := range p.Receivers {
		switch receiver.Codec.Name {
		case core.CodecH264:
			video = receiver
		case core.CodecH265:
			video265 = receiver
			// case core.CodecAAC:
			// 	audio = receiver
		}
	}

	for {
		packet, err := p.streamReader.Next()
		if err != nil {
			return err
		}
		switch packet.Codec {
		case "H264":
			if video != nil {
				pkt := &rtp.Packet{
					Header: rtp.Header{
						Timestamp: core.Now90000(),
					},
					Payload: annexb.EncodeToAVCC(packet.Data),
				}
				video.Input(pkt)
			}
		case "H265":
			if video265 != nil {
				pkt := &rtp.Packet{
					Header: rtp.Header{
						Timestamp: core.Now90000(),
					},
					Payload: annexb.EncodeToAVCC(packet.Data),
				}
				video265.Input(pkt)
			}
			// case "AAC":
			// 	pkt := &rtp.Packet{
			// 		Header: rtp.Header{
			// 			Timestamp: core.Now90000(),
			// 		},
			// 		Payload: packet.Data,
			// 	}
			// 	audio.Input(pkt)
		}
	}
}

func (p *Producer) Stop() error {
	streamCode, previewHandle, _ := StreamParams(p.streamKind)
	_ = stopStream(p.bcConn, streamCode, previewHandle, p.streamMsgNum)
	return p.Connection.Stop()
}

func (p *Producer) hasVideoCodec(name string) bool {
	for _, m := range p.Medias {
		if m.Kind == core.KindVideo && len(m.Codecs) > 0 && m.Codecs[0].Name == name {
			return true
		}
	}
	return false
}

func (p *Producer) hasAudioCodec(name string) bool {
	for _, m := range p.Medias {
		if m.Kind == core.KindAudio && len(m.Codecs) > 0 && m.Codecs[0].Name == name {
			return true
		}
	}
	return false
}

func (p *Producer) probe() error {
	var packets int

	msgNum := p.bcConn.NextMessageNum()
	reader, err := p.bcConn.startStream(p.streamKind, msgNum)
	if err != nil {
		return err
	}
	p.streamMsgNum = msgNum
	p.streamReader = reader

	for packets < 30 {
		packet, err := p.streamReader.Next()
		if err != nil {
			return err
		}
		switch packet.Codec {
		case "H264":
			avcc := annexb.EncodeToAVCC(packet.Data)
			if len(avcc) >= 5 && h264.IsKeyframe(avcc) && !p.hasVideoCodec(core.CodecH264) {
				codec := h264.AVCCToCodec(avcc)
				p.Medias = append(p.Medias, &core.Media{
					Kind:      core.KindVideo,
					Direction: core.DirectionRecvonly,
					Codecs:    []*core.Codec{codec},
				})
			}
		case "H265":
			avcc := annexb.EncodeToAVCC(packet.Data)
			if len(avcc) >= 5 && h265.IsKeyframe(avcc) && !p.hasVideoCodec(core.CodecH265) {
				codec := h265.AVCCToCodec(avcc)
				p.Medias = append(p.Medias, &core.Media{
					Kind:      core.KindVideo,
					Direction: core.DirectionRecvonly,
					Codecs:    []*core.Codec{codec},
				})
			}
		case "AAC":
			if !p.hasAudioCodec(core.CodecAAC) {
				codec := aac.ConfigToCodec(packet.Data)
				p.Medias = append(p.Medias, &core.Media{
					Kind:      core.KindAudio,
					Direction: core.DirectionRecvonly,
					Codecs:    []*core.Codec{codec},
				})
			}
		}
		packets++
	}

	return nil
}
