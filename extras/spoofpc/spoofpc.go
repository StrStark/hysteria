// Package spoofpc is a net.PacketConn that carries QUIC packets between two of
// the operator's own servers inside forged-source ICMP echo replies, the same
// wire form Fleet's "spoof tunnel" uses. It lets Hysteria 2 run over a path
// where only whitelisted ("white") source IPs survive the censor's filter:
// every outgoing datagram is sent to the far server's REAL address with the IP
// source forged to a white IP, and inbound datagrams are captured with
// AF_PACKET (before reverse-path filtering) and reported as coming from the
// far server's real address, so quic-go's replies always target the real peer
// and never the forged source. Both ends run one of these; it is the same trick
// as a plain spoof tunnel, lifted from the IP layer (a TUN) to the UDP-packet
// layer (a PacketConn), so there is no inner interface and no double wrap.
//
// IPv4 only. Needs root / CAP_NET_RAW. See Fleet internal/spoof/tunnel.go.
package spoofpc

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// magic marks our payload, distinct from the plain tunnel's "FLTN" so a host
// running both never mistakes one for the other.
var magic = [4]byte{'F', 'L', 'H', 'Y'}

// Config is one end's parameters. The two ends mirror each other: each one's
// Src is the other's Accept, and each one's PeerReal is the other's real address.
type Config struct {
	Src      string // forged source IP to stamp on outgoing packets (a white IP)
	PeerReal string // the far server's REAL IP, the fixed destination
	Accept   string // only accept ICMP whose source is this (the peer's Src); "" accepts any
	PeerPort int    // cosmetic UDP port reported for the peer (ICMP has no ports); must be stable and non-zero
	ID       uint16 // stamped in the ICMP id field, 1..65535, demuxes this flow
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// Conn implements net.PacketConn over forged-source ICMP.
type Conn struct {
	sfd, cfd   int
	srcB       [4]byte
	peerB      [4]byte
	acceptB    [4]byte
	haveAccept bool
	id         uint16
	peerAddr   *net.UDPAddr
	localAddr  *net.UDPAddr

	ipid      uint32
	seq       uint32
	writeMu   sync.Mutex
	readDl    atomic.Int64 // unix-nano read deadline, 0 = none
	closed    atomic.Bool
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// New opens the raw send socket and the AF_PACKET capture socket and returns a
// ready PacketConn.
func New(c Config) (*Conn, error) {
	peer, err := netip.ParseAddr(c.PeerReal)
	if err != nil || !peer.Is4() {
		return nil, fmt.Errorf("bad peer %q (want IPv4)", c.PeerReal)
	}
	src, err := netip.ParseAddr(c.Src)
	if err != nil || !src.Is4() {
		return nil, fmt.Errorf("bad src %q (want IPv4)", c.Src)
	}
	if c.ID == 0 {
		return nil, fmt.Errorf("id must be 1..65535")
	}
	port := c.PeerPort
	if port <= 0 {
		port = 443
	}
	cn := &Conn{
		srcB:      src.As4(),
		peerB:     peer.As4(),
		id:        c.ID,
		peerAddr:  &net.UDPAddr{IP: peer.AsSlice(), Port: port},
		localAddr: &net.UDPAddr{IP: net.IPv4zero, Port: port},
	}
	if c.Accept != "" {
		a, err := netip.ParseAddr(c.Accept)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("bad accept %q (want IPv4)", c.Accept)
		}
		cn.acceptB, cn.haveAccept = a.As4(), true
	}
	// Raw send socket: we write the whole IP header ourselves.
	cn.sfd, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw send socket (needs root/CAP_NET_RAW): %w", err)
	}
	// Capture socket: inbound ICMP, seen before reverse-path filtering.
	cn.cfd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP)))
	if err != nil {
		unix.Close(cn.sfd)
		return nil, fmt.Errorf("AF_PACKET socket (needs root/CAP_NET_RAW): %w", err)
	}
	// A short recv timeout so ReadFrom can honour deadlines and Close.
	_ = unix.SetsockoptTimeval(cn.cfd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000})
	return cn, nil
}

// icmpReply builds an ICMP echo-reply (type 0) carrying payload. Echo-reply, so
// no kernel answers it.
func icmpReply(id, seq uint16, payload []byte) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = 0
	binary.BigEndian.PutUint16(b[4:6], id)
	binary.BigEndian.PutUint16(b[6:8], seq)
	copy(b[8:], payload)
	binary.BigEndian.PutUint16(b[2:4], csum(b))
	return b
}

func ipHeader(src, dst [4]byte, payloadLen int, ipid uint16) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+payloadLen))
	binary.BigEndian.PutUint16(h[4:6], ipid)
	h[8] = 64
	h[9] = 1
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	binary.BigEndian.PutUint16(h[10:12], csum(h))
	return h
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

// WriteTo wraps p in a forged-source ICMP echo-reply to the real peer. The addr
// is ignored: the destination is always the configured peer.
func (c *Conn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	payload := make([]byte, 4+len(p))
	copy(payload[0:4], magic[:])
	copy(payload[4:], p)
	seq := uint16(atomic.AddUint32(&c.seq, 1))
	icmp := icmpReply(c.id, seq, payload)
	ip := ipHeader(c.srcB, c.peerB, len(icmp), uint16(atomic.AddUint32(&c.ipid, 1)))
	pkt := append(ip, icmp...)
	c.writeMu.Lock()
	err := unix.Sendto(c.sfd, pkt, 0, &unix.SockaddrInet4{Addr: c.peerB})
	c.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// ReadFrom returns the next inner QUIC packet from the peer. The reported addr
// is always the peer's real address, so quic-go sends its replies there.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65536)
	for {
		if c.closed.Load() {
			return 0, nil, net.ErrClosed
		}
		n, _, err := unix.Recvfrom(c.cfd, buf, 0)
		if err != nil {
			if dl := c.readDl.Load(); dl != 0 && time.Now().UnixNano() >= dl {
				return 0, nil, timeoutErr{}
			}
			continue // EAGAIN tick
		}
		if n < 20 {
			continue
		}
		ihl := int(buf[0]&0x0f) * 4
		if buf[0]>>4 != 4 || ihl < 20 || buf[9] != 1 || n < ihl+8+4 {
			continue
		}
		if c.haveAccept && [4]byte(buf[12:16]) != c.acceptB {
			continue
		}
		icmp := buf[ihl:n]
		if icmp[0] != 0 || binary.BigEndian.Uint16(icmp[4:6]) != c.id {
			continue
		}
		body := icmp[8:]
		if len(body) < 4 || [4]byte(body[0:4]) != magic {
			continue
		}
		inner := body[4:]
		nn := copy(p, inner)
		return nn, c.peerAddr, nil
	}
}

func (c *Conn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	unix.Close(c.sfd)
	unix.Close(c.cfd)
	return nil
}

func (c *Conn) LocalAddr() net.Addr { return c.localAddr }

func (c *Conn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDl.Store(0)
	} else {
		c.readDl.Store(t.UnixNano())
	}
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

func (c *Conn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
