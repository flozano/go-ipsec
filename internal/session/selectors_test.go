package session

import (
	"bytes"
	"encoding/binary"
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
	initS.authPeerSelectors = prefixes("192.0.2.0/24")
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222, PeerSelectors: initS.authPeerSelectors}
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
	initS.authPeerSelectors = prefixes("0.0.0.0/0")
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222, PeerSelectors: old}
	// The peer's own view of the SA: its outbound SPI is our inbound one.
	respS.child = &ChildSA{InitiatorSPI: 0x2222, ResponderSPI: 0x1111}
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

// A rekey may narrow the selectors IKE_AUTH negotiated but never widen them,
// and an unusable set keeps the current ones rather than emptying the policy.
func TestRekeyedPeerSelectors(t *testing.T) {
	for _, tc := range []struct {
		name string
		sels []ikemsg.TrafficSelector
		want []netip.Prefix
	}{
		{"narrower", []ikemsg.TrafficSelector{v4Sel("192.0.2.10", "192.0.2.10")}, prefixes("192.0.2.10/32")},
		{"same", []ikemsg.TrafficSelector{v4Sel("192.0.2.0", "192.0.2.255")}, prefixes("192.0.2.0/24")},
		{"wider is clamped", []ikemsg.TrafficSelector{v4Sel("0.0.0.0", "255.255.255.255")}, prefixes("192.0.2.0/24")},
		{"disjoint keeps current", []ikemsg.TrafficSelector{v4Sel("198.51.100.1", "198.51.100.1")}, prefixes("192.0.2.128/25")},
		{"malformed keeps current", []ikemsg.TrafficSelector{v4Sel("192.0.2.20", "192.0.2.10")}, prefixes("192.0.2.128/25")},
		{"none keeps current", nil, prefixes("192.0.2.128/25")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := mirrorSessions(t)
			s.authPeerSelectors = prefixes("192.0.2.0/24")
			s.child = &ChildSA{PeerSelectors: prefixes("192.0.2.128/25")}
			if got := s.rekeyedPeerSelectors(tc.sels); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRandESPSPIAvoidsReservedRange(t *testing.T) {
	for range 10000 {
		b, err := randESPSPI()
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != 4 || binary.BigEndian.Uint32(b) < 256 {
			t.Fatalf("SPI %x is reserved", b)
		}
	}
}
