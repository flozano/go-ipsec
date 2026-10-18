package transport

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"
)

var (
	zeroTime     time.Time
	aLongTimeAgo = time.Unix(1, 0)
)

// maxDatagram bounds a single inbound UDP read. IKE messages and ESP packets
// over NAT-T are well under this; 65535 avoids ever truncating a server frame.
const maxDatagram = 65535

// udpConn is a Conn over a net.PacketConn bound to a single server address.
// The remote address is swappable to support NAT-T port migration (:500→:4500).
type udpConn struct {
	pc     net.PacketConn
	remote atomic.Pointer[net.UDPAddr]
	// prevPort is the server port before the last MigrateToPort, accepted as a
	// source until prevUntil (UnixNano) so replies already in flight from it
	// still arrive.
	prevPort  atomic.Int32
	prevUntil atomic.Int64
	rbuf      []byte
	closed    atomic.Bool
	// hostSocket is set for the default host UDP socket, whose writes don't
	// block, so Send leaves the write deadline alone (see Send).
	hostSocket bool
}

// hostSocketBuffer is the receive and send buffer requested for the host UDP
// socket. Every packet of the tunnel crosses this one socket, and the default
// (about 64 KB on Windows, some 45 full-size packets) overflows on a single
// TCP window's burst. The OS may grant less.
const hostSocketBuffer = 4 << 20

// migrationGrace is how long datagrams from the pre-migration server port are
// still accepted after MigrateToPort.
const migrationGrace = 30 * time.Second

// MigrateToPort switches the remote endpoint to the same host on a new port.
// Used to move IKE/ESP onto the NAT-T port 4500 after NAT detection.
func (u *udpConn) MigrateToPort(port int) {
	old := u.remote.Load()
	if old.Port == port {
		return
	}
	u.prevPort.Store(int32(old.Port))
	u.prevUntil.Store(time.Now().Add(migrationGrace).UnixNano())
	next := &net.UDPAddr{IP: old.IP, Port: port, Zone: old.Zone}
	u.remote.Store(next)
}

// DialUDP resolves serverAddr and opens a datagram socket to it. When dial is
// nil a host UDP socket is used. network is typically "udp".
func DialUDP(ctx context.Context, dial DialFunc, network, serverAddr string) (Conn, error) {
	remote, err := resolveUDP(ctx, network, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("transport: resolve %q: %w", serverAddr, err)
	}
	var pc net.PacketConn
	if dial != nil {
		pc, err = dial(ctx, network, serverAddr)
	} else {
		var uc *net.UDPConn
		uc, err = net.ListenUDP(network, nil)
		if err == nil {
			_ = uc.SetReadBuffer(hostSocketBuffer)
			_ = uc.SetWriteBuffer(hostSocketBuffer)
			pc = uc
		}
	}
	if err != nil {
		return nil, fmt.Errorf("transport: dial %q: %w", serverAddr, err)
	}
	u := &udpConn{pc: pc, rbuf: make([]byte, maxDatagram), hostSocket: dial == nil}
	u.remote.Store(remote)
	return u, nil
}

func (u *udpConn) Send(ctx context.Context, p []byte) error {
	if u.closed.Load() {
		return ErrClosed
	}
	if u.hostSocket {
		// A host UDP write doesn't block: it queues the datagram or fails at
		// once. The deadline is per socket and shared by every sender (the
		// data plane, the driver, keepalives), so one sender's cancellation
		// would otherwise fail another's write, such as a graceful DELETE at
		// shutdown, and every packet would pay two extra syscalls.
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := u.pc.WriteTo(p, u.remote.Load())
		if err != nil && u.closed.Load() {
			return ErrClosed
		}
		return err
	}
	// A custom PacketConn may block under backpressure. Mirror Recv's discipline: the top-of-Send deadline set is authoritative
	// (it also neutralises a leftover aLongTimeAgo from a prior Send's
	// cancellation AfterFunc), and the AfterFunc interrupts a blocked write on
	// plain cancellation. Without it a no-deadline driver send over a blocking
	// transport (e.g. a custom PacketDialer under backpressure) could never
	// observe shutdown: Close() waits for the workers before it closes the
	// socket, and the worker would be stuck inside WriteTo forever.
	if dl, ok := ctx.Deadline(); ok {
		_ = u.pc.SetWriteDeadline(dl)
	} else {
		_ = u.pc.SetWriteDeadline(zeroTime)
	}
	stop := context.AfterFunc(ctx, func() { _ = u.pc.SetWriteDeadline(aLongTimeAgo) })
	defer func() { _ = u.pc.SetWriteDeadline(zeroTime) }()
	defer stop()
	_, err := u.pc.WriteTo(p, u.remote.Load())
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if u.closed.Load() {
			return ErrClosed
		}
	}
	return err
}

func (u *udpConn) Recv(ctx context.Context) ([]byte, error) {
	if u.closed.Load() {
		return nil, ErrClosed
	}
	// Set the read deadline at the top of every Recv: the ctx deadline when present,
	// otherwise an explicit clear. This is the authoritative reset — a prior Recv's
	// cancellation AfterFunc may have left the deadline at aLongTimeAgo (stop() does
	// not wait for an already-running AfterFunc, so the deferred clear below can race
	// it), and resetting here makes any such leftover harmless for this Recv.
	if dl, ok := ctx.Deadline(); ok {
		_ = u.pc.SetReadDeadline(dl)
	} else {
		_ = u.pc.SetReadDeadline(zeroTime)
	}
	// AfterFunc interrupts a blocked read on plain cancellation (e.g. a no-deadline
	// data-plane read at shutdown). The deferred clear keeps the common case tidy;
	// the top-of-Recv reset above is what guarantees correctness against the race.
	stop := context.AfterFunc(ctx, func() { _ = u.pc.SetReadDeadline(aLongTimeAgo) })
	defer func() { _ = u.pc.SetReadDeadline(zeroTime) }()
	defer stop()
	for {
		n, src, err := u.pc.ReadFrom(u.rbuf)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if u.closed.Load() {
				return nil, ErrClosed
			}
			return nil, err
		}
		// Single-peer channel: ignore stray datagrams from other sources. The
		// host and port must match the server's; right after a migration the
		// previous port is accepted too, for replies already in flight.
		if !u.fromServer(src) {
			continue
		}
		return u.rbuf[:n], nil
	}
}

func (u *udpConn) LocalAddr() net.Addr  { return u.pc.LocalAddr() }
func (u *udpConn) RemoteAddr() net.Addr { return u.remote.Load() }

func (u *udpConn) Close() error {
	if u.closed.Swap(true) {
		return nil
	}
	return u.pc.Close()
}

// resolveUDP is net.ResolveUDPAddr bounded by ctx, so a slow DNS lookup
// can't outlast the caller's connect timeout.
func resolveUDP(ctx context.Context, network, addr string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := net.DefaultResolver.LookupPort(ctx, network, portStr)
	if err != nil {
		return nil, err
	}
	ipNet := "ip"
	switch network {
	case "udp4":
		ipNet = "ip4"
	case "udp6":
		ipNet = "ip6"
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, ipNet, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %q", host)
	}
	// Prefer IPv4, as net.ResolveUDPAddr does for "udp".
	pick := ips[0]
	for _, ip := range ips {
		if ip.Is4() || ip.Is4In6() {
			pick = ip
			break
		}
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(pick.Unmap(), uint16(port))), nil
}

// fromServer reports whether src is the server: its host and current port,
// or its pre-migration port during the grace period.
func (u *udpConn) fromServer(src net.Addr) bool {
	remote := u.remote.Load()
	host, port, ok := hostPort(src)
	if !ok || !host.Equal(remote.IP) {
		return false
	}
	if port == remote.Port {
		return true
	}
	return port == int(u.prevPort.Load()) && time.Now().UnixNano() < u.prevUntil.Load()
}

// hostPort extracts the IP and port of a datagram source. A custom
// PacketConn may report a non-UDPAddr (or nil) source.
func hostPort(a net.Addr) (net.IP, int, bool) {
	if ua, ok := a.(*net.UDPAddr); ok && ua != nil {
		return ua.IP, ua.Port, true
	}
	if a == nil {
		return nil, 0, false
	}
	h, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil, 0, false
	}
	port, err := strconv.Atoi(p)
	ip := net.ParseIP(h)
	if err != nil || ip == nil {
		return nil, 0, false
	}
	return ip, port, true
}
