package ipsec

import (
	"net/netip"
	"testing"
)

// FuzzInnerPolicy: the inner-packet policy must never panic, and whatever it
// allows is a well-formed packet from inside the selectors to our address.
func FuzzInnerPolicy(f *testing.F) {
	f.Add(ipv4Packet("10.0.0.5", "10.8.192.7", 40))
	f.Add(ipv6Packet("fd00::1", "fd01::7"))
	p := innerPolicy{
		peer:   []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("fd00::/64")},
		local:  netip.MustParseAddr("10.8.192.7"),
		local6: netip.MustParsePrefix("fd01::7/128"),
	}
	f.Fuzz(func(t *testing.T, pkt []byte) {
		if !p.allows(pkt) {
			return
		}
		switch pkt[0] >> 4 {
		case 4:
			src := netip.AddrFrom4([4]byte(pkt[12:16]))
			if !p.peer[0].Contains(src) || netip.AddrFrom4([4]byte(pkt[16:20])) != p.local {
				t.Fatalf("allowed %v -> %v", src, pkt[16:20])
			}
		case 6:
			src := netip.AddrFrom16([16]byte(pkt[8:24]))
			if !p.peer[1].Contains(src) || !p.local6.Contains(netip.AddrFrom16([16]byte(pkt[24:40]))) {
				t.Fatalf("allowed v6 %v", src)
			}
		default:
			t.Fatalf("allowed IP version %d", pkt[0]>>4)
		}
	})
}
