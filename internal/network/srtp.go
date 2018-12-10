package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/pions/webrtc/pkg/rtcp"
	"github.com/pions/webrtc/pkg/rtp"
)

// TODO: change to handleRTP only
// TODO: Migrate to srtp.Conn
func (m *Manager) handleSRTP(buffer []byte) {
	m.srtpInboundContextLock.Lock()
	defer m.srtpInboundContextLock.Unlock()
	if m.srtpInboundContext == nil {
		fmt.Printf("Got RTP packet but no SRTP Context to handle it \n")
		return
	}

	if len(buffer) > 4 {
		var rtcpPacketType uint8

		r := bytes.NewReader([]byte{buffer[1]})
		if err := binary.Read(r, binary.BigEndian, &rtcpPacketType); err != nil {
			fmt.Println("Failed to check packet for RTCP")
			return
		}

		if rtcpPacketType >= 192 && rtcpPacketType <= 223 {
			decrypted, err := m.srtpInboundContext.DecryptRTCP(buffer)
			if err != nil {
				fmt.Println(err)
				fmt.Println(decrypted)
				return
			}

			handleRTCP(m.getBufferTransports, decrypted)
			return
		}
	}

	packet := &rtp.Packet{}
	if err := packet.Unmarshal(buffer); err != nil {
		fmt.Println("Failed to unmarshal RTP packet")
		return
	}

	if ok := m.srtpInboundContext.DecryptRTP(packet); !ok {
		fmt.Println("Failed to decrypt packet")
		return
	}

	bufferTransport := m.getOrCreateBufferTransports(packet.SSRC, packet.PayloadType)
	if bufferTransport != nil && bufferTransport.RTP != nil {
		select {
		case bufferTransport.RTP <- packet:
		default:
		}
	}

}

// TODO: Migrate to srtcp.Conn
func handleRTCP(getBufferTransports func(uint32) *TransportPair, buffer []byte) {
	//decrypted packets can also be compound packets, so we have to nest our reader loop here.
	compoundPacket := rtcp.NewReader(bytes.NewReader(buffer))
	for {
		_, rawrtcp, err := compoundPacket.ReadPacket()

		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println(err)
			return
		}

		var report rtcp.Packet
		report, _, err = rtcp.Unmarshal(rawrtcp)
		if err != nil {
			fmt.Println(err)
			return
		}

		f := func(ssrc uint32) {
			bufferTransport := getBufferTransports(ssrc)
			if bufferTransport != nil && bufferTransport.RTCP != nil {
				select {
				case bufferTransport.RTCP <- report:
				default:
				}
			}
		}

		for _, ssrc := range report.DestinationSSRC() {
			f(ssrc)
		}
	}
}
