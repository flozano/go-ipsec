package session

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

func v4Sel(start, end string) ikemsg.TrafficSelector {
	return ikemsg.TrafficSelector{
		TSType: ikemsg.TSIPv4AddrRange, EndPort: 65535,
		StartAddr: netip.MustParseAddr(start).AsSlice(), EndAddr: netip.MustParseAddr(end).AsSlice(),
	}
}

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func TestSelectorPrefixes(t *testing.T) {
	v6 := ikemsg.TrafficSelector{
		TSType: ikemsg.TSIPv6AddrRange, EndPort: 65535,
		StartAddr: netip.IPv6Unspecified().AsSlice(),
		EndAddr:   bytes.Repeat([]byte{0xff}, 16),
	}
	for _, c := range []struct {
		name string
		sels []ikemsg.TrafficSelector
		want []netip.Prefix
	}{
		{"single host", []ikemsg.TrafficSelector{v4Sel("192.0.2.10", "192.0.2.10")}, prefixes("192.0.2.10/32")},
		{"full v4", []ikemsg.TrafficSelector{v4Sel("0.0.0.0", "255.255.255.255")}, prefixes("0.0.0.0/0")},
		{"aligned block", []ikemsg.TrafficSelector{v4Sel("10.99.128.0", "10.99.255.255")}, prefixes("10.99.128.0/17")},
		{"unaligned range", []ikemsg.TrafficSelector{v4Sel("10.0.0.1", "10.0.0.6")},
			prefixes("10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32")},
		{"full v6", []ikemsg.TrafficSelector{v6}, prefixes("::/0")},
		{"several", []ikemsg.TrafficSelector{v4Sel("10.0.0.0", "10.0.0.255"), v4Sel("192.168.1.7", "192.168.1.7")},
			prefixes("10.0.0.0/24", "192.168.1.7/32")},
		{"start after end skipped", []ikemsg.TrafficSelector{v4Sel("10.0.0.9", "10.0.0.1")}, nil},
		{"family mismatch skipped", []ikemsg.TrafficSelector{{
			TSType: ikemsg.TSIPv6AddrRange, StartAddr: []byte{10, 0, 0, 1}, EndAddr: []byte{10, 0, 0, 1},
		}}, nil},
	} {
		if got := selectorPrefixes(c.sels); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// On a peer-initiated Child rekey the peer is the initiator, so its side is the
// TSi it offered, not the TSr (which is ours).
func TestChildRekeyResponderRecordsPeerTSi(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	dp := &fakeDataPlane{}
	initS.SetDataPlane(dp)

	inner := ikemsg.Payloads{
		&ikemsg.NotifyPayload{Protocol: ikemsg.ProtocolESP, Type: ikemsg.NotifyRekeySA, SPI: []byte{0, 0, 0x22, 0x22}},
		&ikemsg.SAPayload{Proposals: []ikemsg.Proposal{buildESPProposalCBC(1, []byte{0xAB, 0xCD, 0xEF, 0x08})}},
		&ikemsg.NoncePayload{Data: bytes.Repeat([]byte{0xC2}, nonceLen)},
		&ikemsg.TSiPayload{Selectors: []ikemsg.TrafficSelector{v4Sel("192.0.2.10", "192.0.2.10")}},
		&ikemsg.TSrPayload{Selectors: []ikemsg.TrafficSelector{v4Sel("10.99.0.5", "10.99.0.5")}},
	}
	reqRaw, err := encodeSKWith(respS.ikeSA, respS.initiatorSPI, respS.responderSPI,
		ikemsg.ExchangeCreateChildSA, 0, 9, inner)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := recvCtx(t)
	defer cancel()
	if exit := initS.handleInbound(ctx, reqRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}
	if _, err := respConn.Recv(ctx); err != nil {
		t.Fatal(err)
	}

	want := prefixes("192.0.2.10/32")
	if len(dp.updates) != 1 {
		t.Fatalf("installs = %d, want 1", len(dp.updates))
	}
	if got := dp.updates[0].PeerSelectors; !slices.Equal(got, want) {
		t.Fatalf("installed PeerSelectors = %v, want %v", got, want)
	}
	if !slices.Equal(initS.child.PeerSelectors, want) {
		t.Fatalf("session child PeerSelectors = %v, want %v", initS.child.PeerSelectors, want)
	}
}

// On a Child rekey we initiate, the peer's side is the TSr of its response.
func TestChildRekeyInitiatorRecordsPeerTSr(t *testing.T) {
	initS, respS, respConn := mirrorSessions(t)
	initConn := initS.conn
	old := prefixes("192.0.2.10/32")
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222, PeerSelectors: old}
	respS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	initDP := &fakeDataPlane{}
	initS.SetDataPlane(initDP)
	respS.SetDataPlane(&fakeDataPlane{})

	ctx, cancel := recvCtx(t)
	defer cancel()
	if err := initS.initiateChildRekey(ctx, false); err != nil {
		t.Fatal(err)
	}
	reqRaw, err := respConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hdr, inner, dec, err := respS.decodeIKE(reqRaw)
	if err != nil {
		t.Fatal(err)
	}
	// The responder echoes our offered (full-range) selectors.
	_, offeredTSr := trafficSelectors(inner)
	if err := respS.handleChildRekeyRequest(ctx, hdr, inner, dec, false); err != nil {
		t.Fatal(err)
	}
	respRaw, err := initConn.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if exit := initS.handleInbound(ctx, respRaw, func() {}); exit {
		t.Fatal("unexpected teardown")
	}

	want := selectorPrefixes(offeredTSr)
	if len(want) == 0 || slices.Equal(want, old) {
		t.Fatalf("test setup: response selectors %v must differ from the old ones", want)
	}
	if len(initDP.updates) != 1 {
		t.Fatalf("installs = %d, want 1", len(initDP.updates))
	}
	if got := initDP.updates[0].PeerSelectors; !slices.Equal(got, want) {
		t.Fatalf("installed PeerSelectors = %v, want %v", got, want)
	}
	if !slices.Equal(initS.child.PeerSelectors, want) {
		t.Fatalf("session child PeerSelectors = %v, want %v", initS.child.PeerSelectors, want)
	}
}
