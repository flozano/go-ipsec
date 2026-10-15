package session

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// capturePC is a net.PacketConn that records outbound datagrams and never
// receives; a past read deadline (how a cancelled Recv is interrupted)
// unblocks ReadFrom.
type capturePC struct {
	sent     chan []byte
	unblock  chan struct{}
	stopOnce sync.Once
}

func newCapturePC() *capturePC {
	return &capturePC{sent: make(chan []byte, 8), unblock: make(chan struct{})}
}

func (c *capturePC) stop() { c.stopOnce.Do(func() { close(c.unblock) }) }

func (c *capturePC) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.unblock
	return 0, nil, os.ErrDeadlineExceeded
}

func (c *capturePC) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.sent <- append([]byte(nil), p...)
	return len(p), nil
}

func (c *capturePC) Close() error { c.stop(); return nil }
func (c *capturePC) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}
func (c *capturePC) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}
func (c *capturePC) SetReadDeadline(t time.Time) error {
	if !t.IsZero() && t.Before(time.Now()) {
		c.stop()
	}
	return nil
}
func (c *capturePC) SetWriteDeadline(time.Time) error { return nil }

// firstIKEDatagram runs IKE_SA_INIT against server and returns the first
// datagram sent.
func firstIKEDatagram(t *testing.T, server string) []byte {
	t.Helper()
	pc := newCapturePC()
	s := New(Config{
		Server: server,
		Dialer: func(context.Context, string, string) (net.PacketConn, error) { return pc, nil },
		PSK:    []byte("psk"),
		Logger: slog.New(slog.DiscardHandler),
		// One attempt: the test only needs the first datagram.
		RetransmitBase: time.Second, RetransmitMax: time.Second, RetransmitTries: 1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.IKESAInit(ctx); close(done) }()
	defer func() { cancel(); pc.stop(); <-done }()
	select {
	case d := <-pc.sent:
		return d
	case <-time.After(2 * time.Second):
		t.Fatal("no IKE_SA_INIT sent")
		return nil
	}
}

// A server on the NAT-T port gets IKE with the non-ESP marker from the very
// first message (RFC 7296 §2.23); on 500 the first message is plain IKE.
func TestStartOnNATTPort(t *testing.T) {
	marker := []byte{0, 0, 0, 0}
	if d := firstIKEDatagram(t, "192.0.2.1:4500"); !bytes.Equal(d[:4], marker) || len(d) < 4+28 || d[4+17] != 0x20 {
		t.Fatalf("server on 4500: first datagram doesn't start with the non-ESP marker and an IKEv2 header: % x", d[:min(len(d), 24)])
	}
	if d := firstIKEDatagram(t, "192.0.2.1:500"); bytes.Equal(d[:4], marker) || d[17] != 0x20 {
		t.Fatalf("server on 500: first datagram is not plain IKEv2: % x", d[:min(len(d), 24)])
	}
}
