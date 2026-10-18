package ipsec

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/esp"
	"github.com/n0madic/go-ipsec/internal/session"
	"github.com/n0madic/go-ipsec/internal/transport"
	"github.com/n0madic/go-ipsec/internal/tunnel"
)

// deferredRekeyClient returns a client on an old Child SA (out SPI 2, in SPI 1)
// with a new GCM SA (in 0xAAAA, out 0xBBBB) installed with DeferOutbound, the
// peer's view of the new SA, and a function returning the SPI our next
// outbound packet leaves on.
func deferredRekeyClient(t *testing.T) (*Client, *esp.SA, func() uint32) {
	t.Helper()
	initConn, respConn := transport.MemoryPair()
	t.Cleanup(func() { initConn.Close(); respConn.Close() })
	c := newClient(Config{Logger: discardLogger(), ReplayWindow: 64})
	send := func(ctx context.Context, pkt []byte) error { return initConn.Send(ctx, pkt) }
	oldKey := bytes.Repeat([]byte{0x01}, 32)
	oldSA, err := esp.NewSA(esp.SuiteAESCBC256SHA256, 2, 1, oldKey, oldKey, oldKey, oldKey, 64)
	if err != nil {
		t.Fatal(err)
	}
	c.resetInbound(1, oldSA)
	c.tun = tunnel.New(oldSA, send, tunConfig(netip.MustParseAddr("10.6.0.1"), netip.MustParseAddr("255.255.255.0")))
	t.Cleanup(func() { c.tun.Close() })
	t.Cleanup(c.stopGraceTimers)

	keyIR := bytes.Repeat([]byte{0x11}, 36)
	keyRI := bytes.Repeat([]byte{0x22}, 36)
	c.InstallChildSA(session.ChildSAUpdate{
		NewInSPI: 0xAAAA, NewOutSPI: 0xBBBB, OldInSPI: 1,
		Suite:   esp.SuiteAESGCM256,
		OutEncr: keyRI, InEncr: keyIR,
		DeferOutbound: true,
	})
	peer, err := esp.NewSA(esp.SuiteAESGCM256, 0xAAAA, 0xBBBB, keyIR, nil, keyRI, nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	outSPI := func() uint32 {
		t.Helper()
		if _, err := c.tun.TunnelConn().Write(append([]byte{0x45}, make([]byte, 27)...)); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		raw, err := respConn.Recv(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return binary.BigEndian.Uint32(raw[:4])
	}
	return c, peer, outSPI
}

// Answering a peer-initiated rekey, outbound stays on the old SA until the
// peer sends on the new one.
func TestDeferredOutboundSwitchesOnFirstInbound(t *testing.T) {
	c, peer, outSPI := deferredRekeyClient(t)
	if got := outSPI(); got != 2 {
		t.Fatalf("outbound SPI before the peer used the new SA = %#x, want the old SA's 0x2", got)
	}
	pkt, err := peer.Encrypt(append([]byte{0x45}, make([]byte, 19)...))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	sent := false
	c.rxLoop(ctx, func(ctx context.Context) ([]byte, error) {
		if !sent {
			sent = true
			return pkt, nil
		}
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}, make(chan []byte, 1), func() { t.Error("unexpected onDead") })
	if got := outSPI(); got != 0xBBBB {
		t.Fatalf("outbound SPI after a packet on the new SA = %#x, want 0xbbbb", got)
	}
}

// The peer's DELETE of the old SA (CommitOutbound) also switches outbound, and
// a later commit is a no-op.
func TestDeferredOutboundSwitchesOnCommit(t *testing.T) {
	c, _, outSPI := deferredRekeyClient(t)
	c.CommitOutbound()
	if got := outSPI(); got != 0xBBBB {
		t.Fatalf("outbound SPI after CommitOutbound = %#x, want 0xbbbb", got)
	}
	c.CommitOutbound()
	if got := outSPI(); got != 0xBBBB {
		t.Fatalf("outbound SPI after a second CommitOutbound = %#x, want 0xbbbb", got)
	}
}

// A rekey we initiate supersedes a waiting deferred switch.
func TestImmediateInstallSupersedesDeferredOutbound(t *testing.T) {
	c, _, outSPI := deferredRekeyClient(t)
	key := bytes.Repeat([]byte{0x33}, 36)
	c.InstallChildSA(session.ChildSAUpdate{
		NewInSPI: 0xCCCC, NewOutSPI: 0xDDDD, OldInSPI: 0xAAAA,
		Suite: esp.SuiteAESGCM256, OutEncr: key, InEncr: key,
	})
	if got := outSPI(); got != 0xDDDD {
		t.Fatalf("outbound SPI = %#x, want 0xdddd", got)
	}
	c.CommitOutbound()
	if got := outSPI(); got != 0xDDDD {
		t.Fatalf("a stale deferred SA was committed: outbound SPI = %#x", got)
	}
}
