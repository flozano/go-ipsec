package ikemsg

import (
	"bytes"
	"testing"
)

// seedFullMessage adds a message carrying one of every payload type the
// codec knows, so the fuzzer starts from deep, valid structure.
func seedFullMessage(f *testing.F) {
	ts := []TrafficSelector{{TSType: TSIPv4AddrRange, StartAddr: []byte{0, 0, 0, 0}, EndAddr: []byte{255, 255, 255, 255}, EndPort: 65535}}
	m := &Message{InitiatorSPI: 1, ResponderSPI: 2, Exchange: ExchangeIKESAInit, Flags: FlagResponse,
		Payloads: Payloads{
			&SAPayload{Proposals: []Proposal{{Number: 1, Protocol: ProtocolESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{
				{Type: TransformEncr, ID: 20, KeyLength: 256, HasKeyLength: true}, {Type: TransformDH, ID: 31}}}}},
			&KEPayload{Group: 31, Data: make([]byte, 32)},
			&NoncePayload{Data: bytes.Repeat([]byte{9}, 32)},
			&NotifyPayload{Type: NotifyCookie, Data: []byte{1, 2}},
			&DeletePayload{Protocol: ProtocolESP, SPIs: [][]byte{{1, 2, 3, 4}}},
			&TSiPayload{Selectors: ts}, &TSrPayload{Selectors: ts},
			&ConfigPayload{CfgType: ConfigRequest, Attributes: []ConfigAttr{{Type: 1, Value: []byte{10, 0, 0, 1}}}},
			&IDrPayload{IDType: 2, Data: []byte("x")},
			&AuthPayload{Method: 2, Data: []byte{1}},
			&CertPayload{Encoding: 4, Data: []byte{1}},
			&EAPPayload{Data: []byte{1, 1, 0, 4}},
			&VendorIDPayload{Data: []byte("v")},
			&EncryptedPayload{InnerFirst: PayloadNonce, Data: make([]byte, 40)},
		}}
	raw, err := m.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
}

// FuzzParseRoundTrip: whatever Parse accepts must marshal to something Parse
// accepts again.
func FuzzParseRoundTrip(f *testing.F) {
	seedFullMessage(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := Parse(raw)
		if err != nil {
			return
		}
		out, err := m.Marshal()
		if err != nil {
			return
		}
		if _, err := Parse(out); err != nil {
			t.Fatalf("re-parse of a marshalled message failed: %v", err)
		}
	})
}

// FuzzParsePayloads covers the decrypted inner chain, with the first payload
// type chosen by the fuzzer.
func FuzzParsePayloads(f *testing.F) {
	f.Add(byte(PayloadSA), []byte{0, 0, 0, 12, 0, 0, 0, 8, 1, 1, 0, 0})
	f.Add(byte(PayloadTSi), []byte{0, 0, 0, 24, 1, 0, 0, 0, 7, 0, 0, 16, 0, 0, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255})
	f.Fuzz(func(t *testing.T, first byte, body []byte) {
		_, _ = ParsePayloads(PayloadType(first), body)
	})
}
