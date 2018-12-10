package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/pions/webrtc/pkg/rtp"
)

// Encode/Decode state for a single SSRC
type ssrcState struct {
	ssrc                 uint32
	rolloverCounter      uint32
	rolloverHasProcessed bool
	lastSequenceNumber   uint16
}

type srtpContext struct {
	baseContext

	ssrcStates map[uint32]*ssrcState
}

func NewContextSRTP(masterKey, masterSalt []byte, profile string) (*srtcpContext, error) {
	base, err := newContextBase(masterKey, masterSalt, profile)
	if err != nil {
		return nil, err
	}

	c := srtpContext{
		baseContext: base,
		ssrcStates:  make(map[uint32]*ssrcState),
	}

	if c.sessionKey, err = c.generateSessionKey(labelSRTPEncryption); err != nil {
		return nil, err
	} else if c.sessionSalt, err = c.generateSessionSalt(labelSRTPSalt); err != nil {
		return nil, err
	} else if c.sessionAuthTag, err = c.generateSessionAuthTag(labelSRTPAuthenticationTag); err != nil {
		return nil, err
	} else if c.block, err = aes.NewCipher(c.sessionKey); err != nil {
		return nil, err
	}
}

// TODO: either migrate to working on []byte or abandon
// interface and move to the srtp sub-package

// Decrypt decrypts a RTP packet with an encrypted payload
func (c *srtpContext) Decrypt(packet *rtp.Packet) bool {
	s := c.getSSRCState(packet.SSRC)

	c.updateRolloverCount(packet.SequenceNumber, s)

	// Extract auth tag and verify it (TODO re-enable auth tag verification #270)
	// auth := packet.Payload[len(packet.Payload)-10:]
	fullPkt := packet.Raw[:]
	fullPkt = append(fullPkt, make([]byte, 4)...)
	binary.BigEndian.PutUint32(fullPkt[len(fullPkt)-4:], s.rolloverCounter)

	// (TODO re-enable auth tag verification #270)
	// verified, err := c.verifyAuthTag(fullPkt, auth, c.sessionAuthTag)
	// if err != nil || !verified {
	// 	return false
	// }

	stream := cipher.NewCTR(c.block, c.generateCounter(packet.SequenceNumber, s.rolloverCounter, s.ssrc, c.sessionSalt))
	stream.XORKeyStream(packet.Payload, packet.Payload)

	packet.Payload = packet.Payload[:len(packet.Payload)-10]

	// Replace payload with decrypted
	packet.Raw = packet.Raw[0:packet.PayloadOffset]
	packet.Raw = append(packet.Raw, packet.Payload...)

	return true
}

// EncryptRTP Encrypts a SRTP packet in place
func (c *srtpContext) EncryptRTP(packet *rtp.Packet) bool {
	s := c.getSSRCState(packet.SSRC)

	c.updateRolloverCount(packet.SequenceNumber, s)

	stream := cipher.NewCTR(c.block, c.generateCounter(packet.SequenceNumber, s.rolloverCounter, s.ssrc, c.sessionSalt))
	stream.XORKeyStream(packet.Payload, packet.Payload)

	fullPkt, err := packet.Marshal()
	if err != nil {
		return false
	}

	fullPkt = append(fullPkt, make([]byte, 4)...)
	binary.BigEndian.PutUint32(fullPkt[len(fullPkt)-4:], s.rolloverCounter)

	authTag, err := c.generateAuthTag(fullPkt, c.sessionAuthTag)
	if err != nil {
		return false
	}

	packet.Payload = append(packet.Payload, authTag...)

	return true
}

// https://tools.ietf.org/html/rfc3550#appendix-A.1
func (c *srtpContext) updateRolloverCount(sequenceNumber uint16, s *ssrcState) {
	if !s.rolloverHasProcessed {
		s.rolloverHasProcessed = true
	} else if sequenceNumber == 0 { // We exactly hit the rollover count

		// Only update rolloverCounter if lastSequenceNumber is greater then maxROCDisorder
		// otherwise we already incremented for disorder
		if s.lastSequenceNumber > maxROCDisorder {
			s.rolloverCounter++
		}
	} else if s.lastSequenceNumber < maxROCDisorder && sequenceNumber > (maxSequenceNumber-maxROCDisorder) {
		// Our last sequence number incremented because we crossed 0, but then our current number was within maxROCDisorder of the max
		// So we fell behind, drop to account for jitter
		s.rolloverCounter--
	} else if sequenceNumber < maxROCDisorder && s.lastSequenceNumber > (maxSequenceNumber-maxROCDisorder) {
		// our current is within a maxROCDisorder of 0
		// and our last sequence number was a high sequence number, increment to account for jitter
		s.rolloverCounter++
	}
	s.lastSequenceNumber = sequenceNumber
}

func (c *srtpContext) getSSRCState(ssrc uint32) *ssrcState {
	s, ok := c.ssrcStates[ssrc]
	if ok {
		return s
	}

	s = &ssrcState{ssrc: ssrc}
	c.ssrcStates[ssrc] = s
	return s
}
