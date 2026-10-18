package ipsec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/n0madic/go-ipsec/internal/esp"
)

// Cost of unauthenticated datagrams on the receive loop: what an attacker who
// can send to our NAT-T port makes us spend per datagram, and that nothing of
// it reaches the netstack or the IKE driver.

func forgedIKE() []byte {
	dg := make([]byte, 4+28+64) // non-ESP marker, IKEv2 header, junk
	rand.Read(dg[4:])
	dg[4+17] = 0x20 // IKEv2
	binary.BigEndian.PutUint32(dg[4+24:], 28+64)
	return dg
}

func benchRx(b *testing.B, c *Client, dgs [][]byte) {
	b.Helper()
	inbox := make(chan []byte, 16)
	delivered := 0
	c.tun.SetInbound(func([]byte) { delivered++ })
	ctx, cancel := context.WithCancel(context.Background())
	i := 0
	b.ReportAllocs()
	b.ResetTimer()
	c.rxLoop(ctx, func(context.Context) ([]byte, error) {
		if i == b.N {
			cancel()
			return nil, ctx.Err()
		}
		dg := dgs[i%len(dgs)]
		i++
		return dg, nil
	}, inbox, func() { b.Fatal("onDead") })
	b.StopTimer()
	if delivered != 0 || len(inbox) != 0 {
		b.Fatalf("forged datagrams got through: %d delivered, %d queued for the driver", delivered, len(inbox))
	}
}

// IKE-looking datagrams for no IKE SA of ours stop at the SPI pre-filter.
func BenchmarkRxForgedIKE(b *testing.B) {
	c := newBareClient(b, "10.0.0.2")
	dgs := make([][]byte, 256)
	for i := range dgs {
		dgs[i] = forgedIKE()
	}
	benchRx(b, c, dgs)
}

// ESP with a live SPI and garbage contents: refused by authentication.
func BenchmarkRxForgedESP(b *testing.B) {
	c, _ := newGCMClient(b)
	dgs := make([][]byte, 256)
	for i := range dgs {
		dgs[i] = make([]byte, 1400)
		rand.Read(dgs[i])
		binary.BigEndian.PutUint32(dgs[i][0:4], 0x1111)
		binary.BigEndian.PutUint32(dgs[i][4:8], uint32(i+1))
	}
	benchRx(b, c, dgs)
}

// A replayed genuine packet: refused by the replay window before decryption.
func BenchmarkRxReplayedESP(b *testing.B) {
	c, peer := newGCMClient(b)
	pkt, err := peer.Encrypt(append([]byte{0x45}, make([]byte, 1380)...))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := c.lookupInbound(0x1111).Decrypt(pkt); err != nil {
		b.Fatal(err) // now in the window
	}
	benchRx(b, c, [][]byte{pkt})
}

// newGCMClient is a bare client with an AES-GCM inbound SA on SPI 0x1111 and
// the peer's side of it.
func newGCMClient(b *testing.B) (*Client, *esp.SA) {
	b.Helper()
	c := newBareClient(b, "10.0.0.2")
	key := bytes.Repeat([]byte{0x11}, 36)
	in, err := esp.NewSA(esp.SuiteAESGCM256, 0x2222, 0x1111, key, nil, key, nil, 64)
	if err != nil {
		b.Fatal(err)
	}
	peer, err := esp.NewSA(esp.SuiteAESGCM256, 0x1111, 0x2222, key, nil, key, nil, 64)
	if err != nil {
		b.Fatal(err)
	}
	c.resetInbound(0x1111, in)
	return c, peer
}
