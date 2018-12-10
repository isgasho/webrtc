package webrtc

import (
	"github.com/pions/webrtc/pkg/media"
	"github.com/pions/webrtc/pkg/rtcp"
	"github.com/pions/webrtc/pkg/rtp"
)

// RTCTrack represents a track that is communicated
type RTCTrack struct {
	ID          string
	PayloadType uint8
	Kind        RTCRtpCodecType
	Label       string
	Ssrc        uint32
	Codec       *RTCRtpCodec
	Packets     <-chan *rtp.Packet     // Receive RTP
	RTCPPackets <-chan rtcp.Packet     // Receive RTCP
	Samples     chan<- media.RTCSample // Samples to payload
	RawRTP      chan<- *rtp.Packet     // Send RTP
}
