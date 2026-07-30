package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// ======================= 客户端多连接池 =======================
type ClientConnPool struct {
	mu      sync.RWMutex
	conns   []*quic.Conn
	streams []*quic.Stream
	idx     uint64
}

func NewClientConnPool() *ClientConnPool {
	return &ClientConnPool{
		conns:   make([]*quic.Conn, 0),
		streams: make([]*quic.Stream, 0),
	}
}

func (p *ClientConnPool) Add(conn *quic.Conn, stream *quic.Stream) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns = append(p.conns, conn)
	p.streams = append(p.streams, stream)
}

func (p *ClientConnPool) Size() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.conns)
}

func (p *ClientConnPool) SendDatagramOrStream(frame []byte, useDatagram bool) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	n := len(p.conns)
	if n == 0 {
		return fmt.Errorf("no active connections in pool")
	}

	curr := atomic.AddUint64(&p.idx, 1)
	i := int(curr % uint64(n))

	conn := p.conns[i]
	stream := p.streams[i]

	if useDatagram && len(frame) > 0 {
		if err := conn.SendDatagram(frame); err == nil {
			return nil
		}
	}
	return writeStreamFrame(stream, frame)
}

func (p *ClientConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range p.conns {
		c.CloseWithError(0, "Pool closed")
	}
	p.conns = nil
	p.streams = nil
}

// ======================= 服务端 Session 连接管理 =======================
type ServerSession struct {
	clientID string
	mu       sync.RWMutex
	conns    []*quic.Conn
	streams  []*quic.Stream
	idx      uint64
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewServerSession(parentCtx context.Context, clientID string) *ServerSession {
	ctx, cancel := context.WithCancel(parentCtx)
	return &ServerSession{
		clientID: clientID,
		conns:    make([]*quic.Conn, 0),
		streams:  make([]*quic.Stream, 0),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (s *ServerSession) AddConn(conn *quic.Conn, stream *quic.Stream) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns = append(s.conns, conn)
	s.streams = append(s.streams, stream)
}

func (s *ServerSession) Send(frame []byte, useDatagram bool) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.conns)
	if n == 0 {
		return fmt.Errorf("no connections for session %s", s.clientID)
	}

	curr := atomic.AddUint64(&s.idx, 1)
	i := int(curr % uint64(n))

	conn := s.conns[i]
	stream := s.streams[i]

	if useDatagram && len(frame) > 0 {
		if err := conn.SendDatagram(frame); err == nil {
			return nil
		}
	}
	return writeStreamFrame(stream, frame)
}

func (s *ServerSession) Close() {
	s.cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		c.CloseWithError(0, "Session closed")
	}
}
