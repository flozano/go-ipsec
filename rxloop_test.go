package ipsec

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A failing socket must end the tunnel through onDead rather than leave the
// receive loop silently gone.
func TestRxLoopDeclaresDeadOnReceiveFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		wantCalls int32
	}{
		{"closed socket", net.ErrClosed, 1},
		{"repeated errors", errors.New("recvfrom: network is down"), rxMaxErrors},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newBareClient(t, "10.0.0.2")
			var calls atomic.Int32
			recv := func(context.Context) ([]byte, error) {
				calls.Add(1)
				return nil, tc.err
			}
			dead := make(chan struct{})
			done := make(chan struct{})
			go func() {
				c.rxLoop(context.Background(), recv, make(chan []byte, 1), func() { close(dead) })
				close(done)
			}()
			select {
			case <-dead:
			case <-time.After(10 * time.Second):
				t.Fatal("onDead not called")
			}
			<-done
			if got := calls.Load(); got != tc.wantCalls {
				t.Fatalf("receive attempts = %d, want %d", got, tc.wantCalls)
			}
		})
	}
}

// A transient error followed by a good read resets the failure count, and a
// cancelled context exits without declaring the tunnel dead.
func TestRxLoopRecoversFromTransientErrors(t *testing.T) {
	c := newBareClient(t, "10.0.0.2")
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	recv := func(ctx context.Context) ([]byte, error) {
		n := calls.Add(1)
		switch {
		case n%3 != 0 && n < 3*rxMaxErrors:
			return nil, errors.New("transient")
		case n < 3*rxMaxErrors:
			return []byte{0xFF}, nil // NAT keepalive: ignored
		}
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	dead := false
	c.rxLoop(ctx, recv, make(chan []byte, 1), func() { dead = true })
	if dead {
		t.Fatal("onDead called for errors that never reached the limit in a row")
	}
}
