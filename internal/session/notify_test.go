package session

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// A responder refusing our credentials surfaces as ErrAuthenticationFailed,
// with the notify named in the message.
func TestIKEAuthAuthenticationFailed(t *testing.T) {
	s, respConn, _ := spoofPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		rs := New(Config{Logger: slog.New(slog.DiscardHandler)})
		if _, _, _, err := respondSAInit(ctx, respConn, rs, bytes.Repeat([]byte{0x42}, 32), gcmIKESuite()); err != nil {
			return
		}
		raw3, err := respConn.Recv(ctx)
		if err != nil {
			return
		}
		hdr3, _, err := rs.decodeSK(raw3)
		if err != nil {
			return
		}
		out, err := rs.encodeSK(ikemsg.ExchangeIKEAuth, ikemsg.FlagResponse, hdr3.MessageID,
			ikemsg.Payloads{&ikemsg.NotifyPayload{Type: ikemsg.NotifyAuthenticationFailed}})
		if err != nil {
			return
		}
		_ = respConn.Send(ctx, out)
	}()
	if err := s.IKESAInit(ctx); err != nil {
		t.Fatal(err)
	}
	err := s.IKEAuth(ctx)
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("err = %v, want ErrAuthenticationFailed", err)
	}
	if !strings.Contains(err.Error(), "AUTHENTICATION_FAILED") {
		t.Fatalf("error %q doesn't name the notify", err)
	}
}

func TestNotifyErrorNames(t *testing.T) {
	for typ, want := range map[uint16]string{
		38: "TS_UNACCEPTABLE (38)",
		36: "INTERNAL_ADDRESS_FAILURE (36)",
		99: "99 (99)",
	} {
		if got := (&NotifyError{Type: typ}).Error(); !strings.HasSuffix(got, want) {
			t.Errorf("type %d: %q, want suffix %q", typ, got, want)
		}
		if errors.Is(&NotifyError{Type: typ}, ErrAuthenticationFailed) {
			t.Errorf("type %d matched ErrAuthenticationFailed", typ)
		}
	}
}
