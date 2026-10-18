package session

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
)

// With a pre-shared key, a responder presenting an identity other than the
// configured RemoteID must be refused even though it holds the key.
func TestPSKResponderIdentityChecked(t *testing.T) {
	for _, tc := range []struct {
		name     string
		remoteID WireID
		wantErr  bool
	}{
		{"matching", WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("vpn.test")}, false},
		{"other name", WireID{Type: uint8(ikemsg.IDTypeFQDN), Data: []byte("expected-gw.test")}, true},
		{"other type", WireID{Type: uint8(ikemsg.IDTypeRFC822), Data: []byte("vpn.test")}, true},
		{"not configured", WireID{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, respConn, psk := spoofPair(t)
			s.cfg.RemoteID = tc.remoteID
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			go runResponderPSK(respConn, psk, cbcSuite(), nil)
			if err := s.IKESAInit(ctx); err != nil {
				t.Fatal(err)
			}
			err := s.IKEAuth(ctx)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "does not match the configured remote ID") {
					t.Fatalf("err = %v, want a remote ID mismatch", err)
				}
				if s.established {
					t.Fatal("session established with the wrong responder identity")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
