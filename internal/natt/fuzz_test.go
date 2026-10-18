package natt

import "testing"

func FuzzClassify(f *testing.F) {
	f.Add([]byte{0xff})
	f.Add([]byte{0, 0, 0, 0, 1, 2, 3})
	f.Add([]byte{0, 0, 1, 0, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, dg []byte) {
		kind, payload := Classify(dg)
		if len(payload) > len(dg) {
			t.Fatalf("payload longer than the datagram")
		}
		if kind == KindIKE && len(dg) >= 4 && (dg[0]|dg[1]|dg[2]|dg[3]) != 0 {
			t.Fatalf("datagram without the non-ESP marker classified as IKE")
		}
	})
}
