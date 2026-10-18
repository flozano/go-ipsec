package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/n0madic/go-ipsec/internal/ikemsg"
	"github.com/n0madic/go-ipsec/internal/transport"
)

// Simultaneous Child SA rekeys (RFC 7296 §2.8.1, §2.25.1): both sides
// rekey the same SA at once. The peer's request is answered as usual, and of
// the two new SAs the one whose exchange holds the lowest of the four nonces
// is deleted by the side that initiated that exchange. Exactly one SA must
// survive on our side, whichever wins.

type collisionRig struct {
	t                *testing.T
	ctx              context.Context
	initS, respS     *Session
	respConn         transport.Conn
	initConn         transport.Conn
	dp               *fakeDataPlane
	ourReq, ourResp  []byte // our CREATE_CHILD_SA and the peer's answer to it
	ourNi, ourNr     []byte
	ourNewIn         uint32
	peerNi, peerNr   []byte
	peerNewIn        uint32 // our inbound SPI of the SA the peer's exchange created
	peerResponseKind ikemsg.NotifyType
}

func newCollisionRig(t *testing.T) *collisionRig {
	t.Helper()
	initS, respS, respConn := mirrorSessions(t)
	initS.child = &ChildSA{InitiatorSPI: 0x1111, ResponderSPI: 0x2222}
	respS.child = &ChildSA{InitiatorSPI: 0x2222, ResponderSPI: 0x1111}
	dp := &fakeDataPlane{}
	initS.SetDataPlane(dp)
	respS.SetDataPlane(&fakeDataPlane{})
	ctx, cancel := recvCtx(t)
	t.Cleanup(cancel)
	return &collisionRig{t: t, ctx: ctx, initS: initS, respS: respS, respConn: respConn, initConn: initS.conn, dp: dp}
}

// startOurs starts our rekey of the current SA and captures the request.
func (r *collisionRig) startOurs() {
	r.t.Helper()
	if err := r.initS.initiateChildRekey(r.ctx, false); err != nil {
		r.t.Fatal(err)
	}
	raw, err := r.respConn.Recv(r.ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	r.ourReq = raw
	r.ourNi = r.initS.pending.child.ni
	r.ourNewIn = r.initS.pending.child.newInSPI
}

// peerAnswersOurs has the peer answer our request.
func (r *collisionRig) peerAnswersOurs() {
	r.t.Helper()
	hdr, inner, dec, err := r.respS.decodeIKE(r.ourReq)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.respS.handleChildRekeyRequest(r.ctx, hdr, inner, dec, false); err != nil {
		r.t.Fatal(err)
	}
	raw, err := r.initConn.Recv(r.ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	r.ourResp = raw
	_, rinner, _, err := r.initS.decodeIKE(raw) // the answer is keyed for us
	if err != nil {
		r.t.Fatal(err)
	}
	for _, p := range rinner {
		if n, ok := p.(*ikemsg.NoncePayload); ok {
			r.ourNr = n.Data
		}
	}
}

// deliverOurResponse hands the peer's answer to our session.
func (r *collisionRig) deliverOurResponse() {
	r.t.Helper()
	if exit := r.initS.handleInbound(r.ctx, r.ourResp, func() {}); exit {
		r.t.Fatal("unexpected teardown")
	}
}

// peerRekeys sends the peer's own rekey of oldSPI (our outbound SPI) with
// nonce ni, and captures our answer.
func (r *collisionRig) peerRekeys(oldSPI uint32, ni []byte) {
	r.t.Helper()
	var spi [4]byte
	binary.BigEndian.PutUint32(spi[:], oldSPI)
	r.peerNi = ni
	req := serverChildRekey(r.t, r.respS, 9, spi[:], []byte{0xAB, 0xCD, 0xEF, 0x09}, ni)
	if exit := r.initS.handleInbound(r.ctx, req, func() {}); exit {
		r.t.Fatal("unexpected teardown")
	}
	raw, err := r.respConn.Recv(r.ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	_, inner, _, err := r.respS.decodeIKE(raw)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, p := range inner {
		switch v := p.(type) {
		case *ikemsg.NoncePayload:
			r.peerNr = v.Data
		case *ikemsg.SAPayload:
			r.peerNewIn = beUint32(v.Proposals[0].SPI)
		case *ikemsg.NotifyPayload:
			if v.Type.IsError() {
				r.peerResponseKind = v.Type
			}
		}
	}
}

// deletesSent returns the Child SA SPIs we sent DELETEs for (draining the
// peer's side of the link without blocking).
func (r *collisionRig) deletesSent() []uint32 {
	r.t.Helper()
	var spis []uint32
	for {
		ctx, cancel := context.WithTimeout(r.ctx, 50e6)
		raw, err := r.respConn.Recv(ctx)
		cancel()
		if err != nil {
			return spis
		}
		_, inner, _, err := r.respS.decodeIKE(raw)
		if err != nil {
			continue
		}
		for _, p := range inner {
			if d, ok := p.(*ikemsg.DeletePayload); ok {
				for _, s := range d.SPIs {
					spis = append(spis, binary.BigEndian.Uint32(s))
				}
			}
		}
	}
}

func lowNonce() []byte  { return bytes.Repeat([]byte{0x00}, nonceLen) }
func highNonce() []byte { return bytes.Repeat([]byte{0xff}, nonceLen) }

func TestSimultaneousChildRekey(t *testing.T) {
	t.Run("peer's exchange redundant: keep ours", func(t *testing.T) {
		r := newCollisionRig(t)
		r.startOurs()
		r.peerRekeys(0x2222, lowNonce())
		if r.peerResponseKind != 0 {
			t.Fatalf("colliding rekey answered with %v, want a normal answer", r.peerResponseKind)
		}
		if len(r.dp.updates) != 1 || !r.dp.updates[0].InboundOnly {
			t.Fatalf("the peer's SA must be installed inbound-only until ours completes: %+v", r.dp.updates)
		}
		if r.initS.child.InitiatorSPI != 0x1111 {
			t.Fatal("the current SA changed before the collision was resolved")
		}
		r.peerAnswersOurs()
		r.deliverOurResponse()

		if r.initS.child.InitiatorSPI != r.ourNewIn {
			t.Fatalf("surviving SA %08x, want ours %08x", r.initS.child.InitiatorSPI, r.ourNewIn)
		}
		if len(r.dp.updates) != 2 || r.dp.updates[1].NewInSPI != r.ourNewIn || r.dp.updates[1].OldInSPI != 0x1111 {
			t.Fatalf("ours must be installed replacing the old SA: %+v", r.dp.updates)
		}
		if !slices.Contains(r.dp.retired, r.peerNewIn) {
			t.Fatalf("the peer's redundant SA was not retired: %v", r.dp.retired)
		}
		if d := r.deletesSent(); !slices.Equal(d, []uint32{0x1111}) {
			t.Fatalf("DELETEs sent %x, want only the old SA 1111 (the peer deletes its own)", d)
		}
	})

	t.Run("our exchange redundant: keep the peer's", func(t *testing.T) {
		r := newCollisionRig(t)
		r.startOurs()
		r.initS.pending.child.ni = lowNonce() // ours now holds the lowest nonce
		r.peerRekeys(0x2222, highNonce())
		r.peerAnswersOurs()
		r.deliverOurResponse()

		if r.initS.child.InitiatorSPI != r.peerNewIn {
			t.Fatalf("surviving SA %08x, want the peer's %08x", r.initS.child.InitiatorSPI, r.peerNewIn)
		}
		if len(r.dp.updates) != 1 {
			t.Fatalf("our redundant SA must never be installed: %+v", r.dp.updates)
		}
		if !slices.Equal(r.dp.used, []uint32{r.peerNewIn}) {
			t.Fatalf("outbound must move to the peer's SA: used %x", r.dp.used)
		}
		if !slices.Contains(r.dp.retired, 0x1111) {
			t.Fatalf("the old SA was not retired: %v", r.dp.retired)
		}
		if d := r.deletesSent(); !slices.Equal(d, []uint32{r.ourNewIn}) {
			t.Fatalf("DELETEs sent %x, want only our redundant SA %08x", d, r.ourNewIn)
		}
	})

	t.Run("our exchange fails: keep the peer's", func(t *testing.T) {
		r := newCollisionRig(t)
		r.startOurs()
		r.peerRekeys(0x2222, highNonce())
		resp, err := encodeSKWith(r.respS.ikeSA, r.respS.initiatorSPI, r.respS.responderSPI,
			ikemsg.ExchangeCreateChildSA, ikemsg.FlagResponse, r.initS.pending.msgID,
			ikemsg.Payloads{&ikemsg.NotifyPayload{Type: ikemsg.NotifyNoProposalChosen}})
		if err != nil {
			t.Fatal(err)
		}
		r.ourResp = resp
		r.deliverOurResponse()
		if r.initS.child.InitiatorSPI != r.peerNewIn || !slices.Equal(r.dp.used, []uint32{r.peerNewIn}) {
			t.Fatalf("after our rekey failed the peer's SA must take over: child %08x used %x",
				r.initS.child.InitiatorSPI, r.dp.used)
		}
	})

	t.Run("retransmitted colliding request is answered from the cache", func(t *testing.T) {
		r := newCollisionRig(t)
		r.startOurs()
		var spi [4]byte
		binary.BigEndian.PutUint32(spi[:], 0x2222)
		req := serverChildRekey(t, r.respS, 9, spi[:], []byte{0xAB, 0xCD, 0xEF, 0x09}, highNonce())
		var answers [][]byte
		for range 2 {
			if exit := r.initS.handleInbound(r.ctx, req, func() {}); exit {
				t.Fatal("unexpected teardown")
			}
			raw, err := r.respConn.Recv(r.ctx)
			if err != nil {
				t.Fatal(err)
			}
			answers = append(answers, raw)
		}
		if !bytes.Equal(answers[0], answers[1]) || len(r.dp.updates) != 1 {
			t.Fatalf("retransmit reprocessed: %d installs, same answer %v", len(r.dp.updates), bytes.Equal(answers[0], answers[1]))
		}
	})
}

// The peer's rekey of an SA our completed rekey just replaced: a collision
// we only see after ours finished.
func TestLateSimultaneousChildRekey(t *testing.T) {
	t.Run("peer's exchange redundant: keep ours", func(t *testing.T) {
		r := newCollisionRig(t)
		r.startOurs()
		r.peerAnswersOurs()
		r.deliverOurResponse()
		if d := r.deletesSent(); !slices.Equal(d, []uint32{0x1111}) {
			t.Fatalf("after our rekey, DELETEs %x, want the old SA 1111", d)
		}
		installs := len(r.dp.updates)
		r.peerRekeys(0x2222, lowNonce())
		if r.peerResponseKind != 0 {
			t.Fatalf("late colliding rekey answered with %v, want a normal answer", r.peerResponseKind)
		}
		if r.initS.child.InitiatorSPI != r.ourNewIn {
			t.Fatalf("surviving SA %08x, want ours %08x", r.initS.child.InitiatorSPI, r.ourNewIn)
		}
		u := r.dp.updates[installs:]
		if len(u) != 1 || !u[0].InboundOnly || !slices.Contains(r.dp.retired, r.peerNewIn) {
			t.Fatalf("the peer's redundant SA must be inbound-only and retired: %+v retired %x", u, r.dp.retired)
		}
	})

	t.Run("our exchange redundant: switch to the peer's", func(t *testing.T) {
		r := newCollisionRig(t)
		r.startOurs()
		r.peerAnswersOurs()
		r.deliverOurResponse()
		if d := r.deletesSent(); !slices.Equal(d, []uint32{0x1111}) {
			t.Fatalf("after our rekey, DELETEs %x, want the old SA 1111", d)
		}
		r.initS.lastRekey.ni = lowNonce() // ours now holds the lowest nonce
		installs := len(r.dp.updates)
		r.peerRekeys(0x2222, highNonce())
		if r.initS.child.InitiatorSPI != r.peerNewIn {
			t.Fatalf("surviving SA %08x, want the peer's %08x", r.initS.child.InitiatorSPI, r.peerNewIn)
		}
		u := r.dp.updates[installs:]
		if len(u) != 1 || u[0].InboundOnly || !u[0].DeferOutbound || u[0].OldInSPI != r.ourNewIn {
			t.Fatalf("the peer's SA must replace ours: %+v", u)
		}
		// Our DELETE for the old SA is still outstanding, so the DELETE for our
		// redundant SA waits in the queue.
		if !slices.Equal(r.initS.deleteQueue, []uint32{r.ourNewIn}) {
			t.Fatalf("delete queue %x, want our redundant SA %08x", r.initS.deleteQueue, r.ourNewIn)
		}
	})
}

// A rekey of an SA we don't have is refused rather than replacing ours.
func TestChildRekeyOfUnknownSA(t *testing.T) {
	r := newCollisionRig(t)
	r.peerRekeys(0x9999, highNonce())
	if r.peerResponseKind != ikemsg.NotifyChildSANotFound {
		t.Fatalf("answered %v, want CHILD_SA_NOT_FOUND", r.peerResponseKind)
	}
	if len(r.dp.updates) != 0 || r.initS.child.InitiatorSPI != 0x1111 {
		t.Fatal("a rekey of an unknown SA changed ours")
	}
}
