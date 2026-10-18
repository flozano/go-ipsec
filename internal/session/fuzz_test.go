package session

import (
	"net/netip"
	"testing"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// FuzzSelectorPrefixes: the prefixes for an address range must lie inside
// it, be disjoint and in order, and cover it without gaps.
func FuzzSelectorPrefixes(f *testing.F) {
	f.Add(false, []byte{10, 0, 0, 0}, []byte{10, 0, 0, 255})
	f.Add(false, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	f.Add(false, []byte{10, 0, 0, 3}, []byte{10, 0, 1, 7})
	f.Add(true, make([]byte, 16), append(make([]byte, 15), 0xff))
	f.Fuzz(func(t *testing.T, v6 bool, start, end []byte) {
		typ := ikemsg.TSIPv4AddrRange
		if v6 {
			typ = ikemsg.TSIPv6AddrRange
		}
		got := selectorPrefixes([]ikemsg.TrafficSelector{{TSType: typ, StartAddr: start, EndAddr: end, EndPort: 65535}})
		s, ok1 := netip.AddrFromSlice(start)
		e, ok2 := netip.AddrFromSlice(end)
		if !ok1 || !ok2 || s.Is4() == v6 || e.BitLen() != s.BitLen() || e.Less(s) {
			if len(got) != 0 {
				t.Fatalf("invalid range %v-%v gave %v", s, e, got)
			}
			return
		}
		if len(got) == 0 || len(got) > 2*s.BitLen() {
			t.Fatalf("%v-%v gave %d prefixes", s, e, len(got))
		}
		next := s
		for i, p := range got {
			if p.Masked().Addr() != next {
				t.Fatalf("%v-%v: prefix %d %v doesn't start at %v", s, e, i, p, next)
			}
			last := lastAddr(p)
			if e.Less(last) {
				t.Fatalf("%v-%v: prefix %v runs past the end", s, e, p)
			}
			if i == len(got)-1 {
				if last != e {
					t.Fatalf("%v-%v: coverage ends at %v", s, e, last)
				}
			} else {
				next = last.Next()
			}
		}
	})
}
