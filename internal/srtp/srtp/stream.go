package srtp

import "github.com/pions/webrtc/pkg/rtp"

// Stream represents a SRTP stream
type Stream struct {
	conn *Conn

	SSRC        uint16
	Payloadtype uint8 // Should be determined based on the SCTP instead
}

func ReadSRTP(buf []byte) (n int, h rtp.Header, err error) {

}

func WriteSRTP(buf []byte, h rtp.Header) (n int, err error) {

}
