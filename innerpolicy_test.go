package ipsec

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func ipv4Packet(src, dst string, total int) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	return p
}

func ipv6Packet(src, dst string) []byte {
	p := make([]byte, 48)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 8)
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(p[8:24], s[:])
	copy(p[24:40], d[:])
	return p
}

func TestInnerPolicy(t *testing.T) {
	v4 := innerPolicy{
		peer:  []netip.Prefix{netip.MustParsePrefix("10.0.0.5/32"), netip.MustParsePrefix("192.168.1.0/24")},
		local: netip.MustParseAddr("10.8.192.7"),
	}
	dual := v4
	dual.peer = append(dual.peer, netip.MustParsePrefix("fd00::/64"))
	dual.local6 = netip.MustParsePrefix("fd01::7/128")

	for _, tc := range []struct {
		name string
		p    innerPolicy
		pkt  []byte
		want bool
	}{
		{"allowed host", v4, ipv4Packet("10.0.0.5", "10.8.192.7", 40), true},
		{"allowed range", v4, ipv4Packet("192.168.1.200", "10.8.192.7", 20), true},
		{"source outside selectors", v4, ipv4Packet("10.0.0.6", "10.8.192.7", 40), false},
		{"not addressed to us", v4, ipv4Packet("10.0.0.5", "10.8.192.8", 40), false},
		{"total length beyond packet", v4, ipv4Packet("10.0.0.5", "10.8.192.7", 41), false},
		{"total length below header", v4, ipv4Packet("10.0.0.5", "10.8.192.7", 19), false},
		{"truncated header", v4, ipv4Packet("10.0.0.5", "10.8.192.7", 40)[:19], false},
		{"no selectors", innerPolicy{local: v4.local}, ipv4Packet("10.0.0.5", "10.8.192.7", 40), false},
		{"no assigned IPv4", innerPolicy{peer: v4.peer}, ipv4Packet("10.0.0.5", "10.9.9.9", 40), true},
		{"not IP", v4, []byte{0xde, 0xad, 0xbe, 0xef}, false},
		{"empty", v4, nil, false},
		{"IPv6 without an assigned prefix", v4, ipv6Packet("fd00::1", "fd01::7"), false},
		{"IPv6 allowed", dual, ipv6Packet("fd00::1", "fd01::7"), true},
		{"IPv6 source outside selectors", dual, ipv6Packet("fd02::1", "fd01::7"), false},
		{"IPv6 not addressed to us", dual, ipv6Packet("fd00::1", "fd01::8"), false},
		{"IPv6 truncated payload", dual, ipv6Packet("fd00::1", "fd01::7")[:47], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.allows(tc.pkt); got != tc.want {
				t.Fatalf("allows = %v, want %v", got, tc.want)
			}
		})
	}
}
