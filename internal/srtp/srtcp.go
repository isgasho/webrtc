package srtp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

type srtcpContext struct {
	baseContext

	index uint32
}

func NewContextSRTCP(masterKey, masterSalt []byte, profile string) (*srtcpContext, error) {
	base, err := newContextBase(masterKey, masterSalt, profile)
	if err != nil {
		return nil, err
	}

	c := srtcpContext{
		baseContext: base,
	}

	if c.sessionKey, err = c.generateSessionKey(labelSRTCPEncryption); err != nil {
		return nil, err
	} else if c.sessionSalt, err = c.generateSessionSalt(labelSRTCPSalt); err != nil {
		return nil, err
	} else if c.sessionAuthTag, err = c.generateSessionAuthTag(labelSRTCPAuthenticationTag); err != nil {
		return nil, err
	} else if c.block, err = aes.NewCipher(c.sessionKey); err != nil {
		return nil, err
	}

}

// Decryp decrypts a buffer that contains a RTCP packet
// We can't pass *rtcp.Packet as the encrypt will obscure significant fields
func (c *srtcpContext) Decrypt(encrypted []byte) ([]byte, error) {
	tailOffset := len(encrypted) - (authTagSize + srtcpIndexSize)
	out := append([]byte{}, encrypted[0:tailOffset]...)

	isEncrypted := encrypted[tailOffset] >> 7
	if isEncrypted == 0 {
		return out, nil
	}

	srtcpIndexBuffer := append([]byte{}, encrypted[tailOffset:tailOffset+srtcpIndexSize]...)
	srtcpIndexBuffer[0] &= 0x7f // unset Encryption bit

	index := binary.BigEndian.Uint32(srtcpIndexBuffer)
	ssrc := binary.BigEndian.Uint32(encrypted[4:])

	stream := cipher.NewCTR(c.block, c.generateCounter(uint16(index&0xffff), index>>16, ssrc, c.sessionSalt))
	stream.XORKeyStream(out[8:], out[8:])

	return out, nil
}

// Encrypt encrypts a buffer that contains a RTCP packet
func (c *srtcpContext) Encrypt(decrypted []byte) ([]byte, error) {
	out := append([]byte{}, decrypted[:]...)
	ssrc := binary.BigEndian.Uint32(decrypted[4:])

	// We roll over early because MSB is used for marking as encrypted
	c.index++
	if c.index >= 2147483647 {
		c.index = 0
	}

	// Encrypt everything after header
	stream := cipher.NewCTR(c.block, c.generateCounter(uint16(c.index&0xffff), c.index>>16, ssrc, c.sessionSalt))
	stream.XORKeyStream(out[8:], out[8:])

	// Add SRTCP Index and set Encryption bit
	out = append(out, make([]byte, 4)...)
	binary.BigEndian.PutUint32(out[len(out)-4:], c.index)
	out[len(out)-4] |= 0x80

	authTag, err := c.generateAuthTag(out, c.sessionAuthTag)
	if err != nil {
		return nil, err
	}
	return append(out, authTag...), nil
}
