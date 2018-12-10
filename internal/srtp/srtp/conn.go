package srtp

import (
	"errors"
	"net"

	"github.com/pions/webrtc/internal/srtp"
)

type Conn struct {
	nextConn net.Conn

	inboundContext  Context
	outboundContext Context

	streams  map[uint16]*Stream
	acceptCh chan *Stream
}

// Config bundles the configuration of a SRTP Conn
type Config struct {
	KeyingMaterial []byte
	Profile        string
}

// Client starts a client-side SRTP conn
func Client(nextConn net.Conn, config *Config) (*Conn, error) {
	return createConn(nextConn, config, true)
}

// Server starts a server-side SRTP conn
func Server(nextConn net.Conn, config *Config) (*Conn, error) {
	return createConn(nextConn, config, false)
}

func createConn(nextConn net.Conn, config *Config, isClient bool) (*Conn, error) {
	localWriteKey, remoteWriteKey := srtp.SplitKeyingMaterial(config.KeyingMaterial, isClient)

	var err error
	inboundContext, err = newContext(config.Component, localWriteKey[0:16], localWriteKey[16:], config.Profile)
	if err != nil {
		return nil, errors.New("failed to build inbound SRTP context")
	}
	outboundContext, err = newContext(config.Component, remoteWriteKey[0:16], remoteWriteKey[16:], config.Profile)
	if err != nil {
		return nil, errors.New("failed to build outbound SRTP context")
	}

	c := &Conn{
		nextConn: nextConn,
	}

	return c, nil
}

// AcceptStream accepts a stream
func (c *Conn) AcceptStream() (*Stream, error) {

}

// OpenStream opens a stream
func (c *Conn) OpenStream(SSRC uint16) (*Stream, error) {

}
