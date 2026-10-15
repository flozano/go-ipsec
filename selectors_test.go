package ipsec

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/session"
	"github.com/n0madic/go-ipsec/internal/transport"
	"github.com/n0madic/go-ipsec/internal/tunnel"
)

// A Child SA rekey replaces RemoteTrafficSelectors before OnRekey callbacks
// run, and the accessor hands out a copy.
func TestRemoteTrafficSelectorsFollowRekey(t *testing.T) {
	initConn, respConn := transport.MemoryPair()
	t.Cleanup(func() { initConn.Close(); respConn.Close() })
	c := newClient(Config{Logger: discardLogger(), ReplayWindow: 64})
	send := func(ctx context.Context, pkt []byte) error { return initConn.Send(ctx, pkt) }

	key := bytes.Repeat([]byte{0x01}, 32)
	sa, err := esp.NewSA(esp.SuiteAESCBC256SHA256, 2, 1, key, key, key, key, 64)
	if err != nil {
		t.Fatal(err)
	}
	c.resetInbound(1, sa)
	c.tun = tunnel.New(sa, send, tunConfig(netip.MustParseAddr("10.6.0.1"), netip.MustParseAddr("255.255.255.0")))
	t.Cleanup(func() { c.tun.Close() })
	t.Cleanup(c.stopGraceTimers)
	c.peerTS = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}

	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32")}
	var seen []netip.Prefix
	c.OnRekey(func() { seen = c.RemoteTrafficSelectors() })

	newKey := bytes.Repeat([]byte{0x11}, 32)
	c.InstallChildSA(session.ChildSAUpdate{
		NewInSPI: 0xAAAA, NewOutSPI: 0xBBBB, OldInSPI: 1,
		Suite:   esp.SuiteAESCBC256SHA256,
		OutEncr: newKey, OutInteg: newKey, InEncr: newKey, InInteg: newKey,
		PeerSelectors: want,
	})

	if !slices.Equal(seen, want) {
		t.Fatalf("OnRekey saw %v, want %v", seen, want)
	}
	got := c.RemoteTrafficSelectors()
	if !slices.Equal(got, want) {
		t.Fatalf("RemoteTrafficSelectors() = %v, want %v", got, want)
	}
	got[0] = netip.MustParsePrefix("0.0.0.0/0")
	if !slices.Equal(c.RemoteTrafficSelectors(), want) {
		t.Fatal("RemoteTrafficSelectors() exposed a mutable internal slice")
	}
}

// Done is closed by Close.
func TestDoneClosedByClose(t *testing.T) {
	c := newClient(Config{Logger: discardLogger()})
	select {
	case <-c.Done():
		t.Fatal("Done closed before Close")
	default:
	}
	_ = c.Close()
	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done not closed after Close")
	}
}
