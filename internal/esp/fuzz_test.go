package esp

import (
	"bytes"
	"testing"
)

// FuzzDecrypt feeds arbitrary packets to both suites' inbound path with fixed
// keys. Seeds are valid packets, so mutations reach the trailer parsing too.
func FuzzDecrypt(f *testing.F) {
	gcmKey := bytes.Repeat([]byte{0x11}, 36)
	cbcKey, cbcInteg := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
	newPair := func(suite Suite) (*SA, *SA) {
		key, integ := gcmKey, []byte(nil)
		if suite == SuiteAESCBC256SHA256 {
			key, integ = cbcKey, cbcInteg
		}
		tx, err := NewSA(suite, 7, 8, key, integ, key, integ, 64)
		if err != nil {
			f.Fatal(err)
		}
		rx, err := NewSA(suite, 8, 7, key, integ, key, integ, 64)
		if err != nil {
			f.Fatal(err)
		}
		return tx, rx
	}
	for _, suite := range []Suite{SuiteAESGCM256, SuiteAESCBC256SHA256} {
		tx, _ := newPair(suite)
		for _, n := range []int{0, 1, 20, 100} {
			pkt, err := tx.Encrypt(append([]byte{0x45}, make([]byte, n)...))
			if err != nil {
				f.Fatal(err)
			}
			f.Add(suite == SuiteAESCBC256SHA256, pkt)
		}
	}
	f.Fuzz(func(t *testing.T, cbc bool, pkt []byte) {
		suite := SuiteAESGCM256
		if cbc {
			suite = SuiteAESCBC256SHA256
		}
		_, rx := newPair(suite)
		inner, err := rx.Decrypt(pkt)
		if err == nil && len(inner) > len(pkt) {
			t.Fatalf("inner datagram (%d bytes) longer than the packet (%d)", len(inner), len(pkt))
		}
	})
}
