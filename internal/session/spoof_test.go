package session

import (
	"context"
	"encoding/binary"
	"log/slog"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/transport"
)

// Unauthenticated datagrams that look like responses must not abort the
// handshake: the initiator drops them and goes on waiting for the real one.

func spoofResponse(spii, spir uint64, msgID uint32, ex ikemsg.ExchangeType, payloads ikemsg.Payloads) []byte {
	m := &ikemsg.Message{InitiatorSPI: spii, ResponderSPI: spir, Exchange: ex,
		Flags: ikemsg.FlagResponse, MessageID: msgID, Payloads: payloads}
	raw, _ := m.Marshal()
	return raw
}

func spoofPair(t *testing.T) (*Session, transport.Conn, []byte) {
	t.Helper()
	psk := []byte("a-strong-preshared-key")
	initConn, respConn := transport.MemoryPair()
	s := New(Config{
		Server:          "mem:500",
		LocalID:         WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("client.test")},
		RemoteID:        WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("vpn.test")},
		PSK:             psk,
		Logger:          slog.New(slog.DiscardHandler),
		RetransmitBase:  2 * time.Second,
		RetransmitMax:   4 * time.Second,
		RetransmitTries: 3,
	})
	s.conn = initConn
	return s, respConn, psk
}

func TestSpoofedSAInitResponsesIgnored(t *testing.T) {
	var group [2]byte
	binary.BigEndian.PutUint16(group[:], ikemsg.DH_X25519)
	for _, tc := range []struct {
		name  string
		spoof []byte
	}{
		{"bare header, other SPIs", spoofResponse(0xdead, 0xbeef, 0, ikemsg.ExchangeIKESAInit, nil)},
		{"NO_PROPOSAL_CHOSEN, other SPIs", spoofResponse(0xdead, 0, 0, ikemsg.ExchangeIKESAInit,
			ikemsg.Payloads{&ikemsg.NotifyPayload{Type: ikemsg.NotifyNoProposalChosen}})},
		{"INVALID_KE in another exchange type", spoofResponse(0xdead, 0, 0, ikemsg.ExchangeInformational,
			ikemsg.Payloads{&ikemsg.NotifyPayload{Type: ikemsg.NotifyInvalidKEPayload, Data: group[:]}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, respConn, psk := spoofPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = respConn.Send(ctx, tc.spoof)
			go runResponderPSK(respConn, psk, cbcSuite(), nil)
			if err := s.IKESAInit(ctx); err != nil {
				t.Fatalf("IKESAInit failed on a spoofed datagram: %v", err)
			}
		})
	}
}

func TestSpoofedIKEAuthResponsesIgnored(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ourSPIs  bool
		payloads ikemsg.Payloads
	}{
		{"other SPIs", false, nil},
		{"our SPIs, no SK payload", true, nil},
		{"our SPIs, forged SK payload", true, ikemsg.Payloads{&ikemsg.EncryptedPayload{
			InnerFirst: ikemsg.PayloadType(36), Data: make([]byte, 64)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, respConn, psk := spoofPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			go runResponderPSK(respConn, psk, cbcSuite(), nil)
			if err := s.IKESAInit(ctx); err != nil {
				t.Fatal(err)
			}
			spii, spir := uint64(0xdead), uint64(0xbeef)
			if tc.ourSPIs {
				spii, spir = s.initiatorSPI, s.responderSPI
			}
			_ = respConn.Send(ctx, spoofResponse(spii, spir, 1, ikemsg.ExchangeIKEAuth, tc.payloads))
			if err := s.IKEAuth(ctx); err != nil {
				t.Fatalf("IKEAuth failed on a spoofed datagram: %v", err)
			}
		})
	}
}

// A spoofed error notify that carries our SPI is still only noted: with no
// genuine answer within the retransmit interval, it is what gets reported.
func TestUnauthenticatedSAInitErrorReportedOnTimeout(t *testing.T) {
	s, respConn, _ := spoofPair(t)
	s.cfg.RetransmitBase = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		raw, err := respConn.Recv(ctx)
		if err != nil {
			return
		}
		m, err := ikemsg.Parse(raw)
		if err != nil {
			return
		}
		_ = respConn.Send(ctx, spoofResponse(m.InitiatorSPI, 0, 0, ikemsg.ExchangeIKESAInit,
			ikemsg.Payloads{&ikemsg.NotifyPayload{Type: ikemsg.NotifyNoProposalChosen}}))
	}()
	err := s.IKESAInit(ctx)
	if err == nil || ctx.Err() != nil {
		t.Fatalf("err = %v, want the NO_PROPOSAL_CHOSEN notify reported", err)
	}
	t.Logf("reported: %v", err)
}
