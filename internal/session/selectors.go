package session

import (
	"net/netip"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// selectorPrefixes returns the address prefixes covered by traffic selectors:
// each selector's [StartAddr, EndAddr] range as the minimal set of prefixes.
// Protocol and port ranges are not represented. Selectors of an unknown type,
// with malformed addresses or with Start > End are skipped.
func selectorPrefixes(sels []ikemsg.TrafficSelector) []netip.Prefix {
	var out []netip.Prefix
	for _, ts := range sels {
		start, ok1 := netip.AddrFromSlice(ts.StartAddr)
		end, ok2 := netip.AddrFromSlice(ts.EndAddr)
		if !ok1 || !ok2 || start.BitLen() != end.BitLen() || end.Less(start) {
			continue
		}
		if (ts.TSType == ikemsg.TSIPv4AddrRange) != start.Is4() {
			continue
		}
		out = append(out, rangePrefixes(start, end)...)
	}
	return out
}

// rangePrefixes returns the minimal set of prefixes covering [start, end]
// (both of the same family, start <= end).
func rangePrefixes(start, end netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for {
		// The largest prefix that starts at start and ends at or before end.
		bits := start.BitLen()
		for b := 0; b <= start.BitLen(); b++ {
			p := netip.PrefixFrom(start, b)
			if p.Masked().Addr() == start && !end.Less(lastAddr(p)) {
				bits = b
				break
			}
		}
		p := netip.PrefixFrom(start, bits)
		out = append(out, p)
		last := lastAddr(p)
		if last == end {
			return out
		}
		start = last.Next()
	}
}

// lastAddr is the highest address in p.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(a)*8; i++ {
		a[i/8] |= 0x80 >> (i % 8)
	}
	last, _ := netip.AddrFromSlice(a)
	return last
}

// trafficSelectors extracts the TSi and TSr payload selectors from a message.
func trafficSelectors(payloads ikemsg.Payloads) (tsi, tsr []ikemsg.TrafficSelector) {
	for _, p := range payloads {
		switch v := p.(type) {
		case *ikemsg.TSiPayload:
			tsi = v.Selectors
		case *ikemsg.TSrPayload:
			tsr = v.Selectors
		}
	}
	return tsi, tsr
}
