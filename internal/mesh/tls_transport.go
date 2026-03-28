//go:build linux

// TLSTransport implements memberlist.Transport using mutual TLS.
// See wire.go for the framing protocol specification.
package mesh

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/hashicorp/memberlist"
)

const (
	connPoolSize = 1024
	readTimeout  = 10 * time.Second
)

// pooledConn wraps a TLS connection with a per-connection mutex to allow
// concurrent writes to different peers without global lock contention.
// Follows Alertmanager's tlsConn pattern.
type pooledConn struct {
	mu   sync.Mutex
	conn net.Conn
	live bool
}

func (pc *pooledConn) writePacket(payload []byte, from string) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if err := WritePacket(pc.conn, payload, from); err != nil {
		pc.live = false
		return err
	}
	return nil
}

func (pc *pooledConn) alive() bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.live
}

func (pc *pooledConn) Close() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.live = false
	return pc.conn.Close()
}

// TLSTransport implements memberlist.Transport using mutual TLS.
type TLSTransport struct {
	logger       *slog.Logger
	listener     net.Listener
	clientTLS    *tls.Config
	advertise    net.Addr
	pool         *lru.Cache
	poolMu       sync.Mutex
	packetCh     chan *memberlist.Packet
	streamCh     chan net.Conn
	shutdown     chan struct{}
	wg           sync.WaitGroup
	shutdownOnce sync.Once
	connsMu      sync.Mutex
	conns        map[net.Conn]struct{}
}

// NewTLSTransport creates a TLS transport that listens on the given address.
func NewTLSTransport(logger *slog.Logger, bindAddr string, bindPort int, serverTLS, clientTLS *tls.Config) (*TLSTransport, error) {
	addr := fmt.Sprintf("%s:%d", bindAddr, bindPort)
	ln, err := tls.Listen("tcp", addr, serverTLS)
	if err != nil {
		return nil, fmt.Errorf("tls listen %s: %w", addr, err)
	}

	pool, err := lru.NewWithEvict(connPoolSize, func(key, value interface{}) {
		if pc, ok := value.(*pooledConn); ok {
			pc.Close()
		}
	})
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	t := &TLSTransport{
		logger:    logger,
		listener:  ln,
		clientTLS: clientTLS,
		pool:      pool,
		packetCh:  make(chan *memberlist.Packet, 256),
		streamCh:  make(chan net.Conn, 16),
		shutdown:  make(chan struct{}),
		conns:     make(map[net.Conn]struct{}),
	}

	t.wg.Add(1)
	go t.acceptLoop()

	return t, nil
}

// FinalAdvertiseAddr returns the advertised address for this transport.
func (t *TLSTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	addr := t.listener.Addr().(*net.TCPAddr)
	advertiseIP := addr.IP
	if ip != "" {
		advertiseIP = net.ParseIP(ip)
		if advertiseIP == nil {
			return nil, 0, fmt.Errorf("invalid advertise IP: %s", ip)
		}
	}
	advertisePort := addr.Port
	if port > 0 {
		advertisePort = port
	}
	t.advertise = &net.TCPAddr{IP: advertiseIP, Port: advertisePort}
	return advertiseIP, advertisePort, nil
}

// WriteTo sends a packet-type message to the given address.
// Per-connection mutex (pooledConn.mu) allows concurrent writes to different
// peers. Pool lock held only during borrow, not during writes — matching
// Alertmanager's borrowConnection + writePacket pattern.
func (t *TLSTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	pc, err := t.getConn(addr)
	if err != nil {
		return time.Time{}, err
	}

	if err := pc.writePacket(b, t.advertise.String()); err != nil {
		return time.Time{}, err
	}

	return time.Now(), nil
}

// PacketCh returns a channel of incoming packets.
func (t *TLSTransport) PacketCh() <-chan *memberlist.Packet {
	return t.packetCh
}

// DialTimeout opens a stream-type connection to the given address.
func (t *TLSTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	conn, err := t.dialTLS(addr, timeout)
	if err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte{ConnStream}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write stream marker: %w", err)
	}

	return conn, nil
}

// StreamCh returns a channel of incoming stream connections.
func (t *TLSTransport) StreamCh() <-chan net.Conn {
	return t.streamCh
}

// Shutdown stops the transport and closes all connections.
// Safe to call multiple times.
func (t *TLSTransport) Shutdown() error {
	t.shutdownOnce.Do(func() {
		close(t.shutdown)
		t.listener.Close()

		// Close all tracked inbound connections so blocked readers unblock.
		t.connsMu.Lock()
		for c := range t.conns {
			c.Close()
		}
		t.connsMu.Unlock()

		t.wg.Wait()

		// Purge fires the eviction callback (pooledConn.Close) for each entry.
		t.poolMu.Lock()
		t.pool.Purge()
		t.poolMu.Unlock()
	})
	return nil
}

func (t *TLSTransport) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			select {
			case <-t.shutdown:
				return
			default:
				t.logger.Warn("tls accept", "err", err)
				continue
			}
		}
		t.wg.Add(1)
		go t.handleConn(conn)
	}
}

func (t *TLSTransport) handleConn(conn net.Conn) {
	defer t.wg.Done()
	t.trackConn(conn)
	defer t.untrackConn(conn)

	var typeBuf [1]byte
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	if _, err := io.ReadFull(conn, typeBuf[:]); err != nil {
		t.logger.Debug("read type byte", "err", err, "remote", conn.RemoteAddr())
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	switch typeBuf[0] {
	case ConnPacket:
		t.handlePacketConn(conn)
	case ConnStream:
		// Pass ownership to memberlist via StreamCh. Don't close here.
		select {
		case t.streamCh <- conn:
		case <-t.shutdown:
			conn.Close()
		}
	default:
		t.logger.Warn("unknown message type", "type", typeBuf[0], "remote", conn.RemoteAddr())
		conn.Close()
	}
}

func (t *TLSTransport) handlePacketConn(conn net.Conn) {
	defer conn.Close()

	for {
		select {
		case <-t.shutdown:
			return
		default:
		}

		payload, from, err := ReadPacket(conn)
		if err != nil {
			if err != io.EOF {
				t.logger.Debug("read packet", "err", err, "remote", conn.RemoteAddr())
			}
			return
		}

		fromAddr, err := parseTCPAddr(from)
		if err != nil {
			t.logger.Warn("parse from address", "from", from, "err", err)
			continue
		}

		select {
		case t.packetCh <- &memberlist.Packet{Buf: payload, From: fromAddr, Timestamp: time.Now()}:
		case <-t.shutdown:
			return
		}
	}
}

// getConn returns a pooled connection or dials a new one.
// Follows Alertmanager's borrowConnection pattern: pool lock held for the
// entire operation including dial. This is trivially correct — no concurrent
// dial races, no double-check needed. The serialization cost is acceptable
// because dials are infrequent (connections are long-lived and pooled).
func (t *TLSTransport) getConn(addr string) (*pooledConn, error) {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()

	if val, ok := t.pool.Get(addr); ok {
		pc := val.(*pooledConn)
		if pc.alive() {
			return pc, nil
		}
		// Remove dead entry so it doesn't waste a pool slot.
		t.pool.Remove(addr)
	}

	conn, err := t.dialTLS(addr, readTimeout)
	if err != nil {
		return nil, err
	}

	// Establish as packet connection.
	if _, err := conn.Write([]byte{ConnPacket}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write packet marker: %w", err)
	}

	pc := &pooledConn{conn: conn, live: true}
	t.pool.Add(addr, pc)
	return pc, nil
}

func (t *TLSTransport) trackConn(conn net.Conn) {
	t.connsMu.Lock()
	t.conns[conn] = struct{}{}
	t.connsMu.Unlock()
}

func (t *TLSTransport) untrackConn(conn net.Conn) {
	t.connsMu.Lock()
	delete(t.conns, conn)
	t.connsMu.Unlock()
}

func (t *TLSTransport) dialTLS(addr string, timeout time.Duration) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, t.clientTLS)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	return conn, nil
}

// parseTCPAddr parses a host:port string without DNS resolution.
// Rejects non-IP hostnames to avoid unexpected lookups on peer-controlled data.
func parseTCPAddr(s string) (*net.TCPAddr, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("non-IP host: %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port out of range: %d", port)
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}
