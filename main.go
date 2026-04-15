package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ======================= 全局日志 =======================
var log *zap.SugaredLogger

func initLogger(level string) {
	config := zap.NewDevelopmentConfig()
	var l zapcore.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = zap.InfoLevel
	}
	config.Level = zap.NewAtomicLevelAt(l)
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	baseLogger, _ := config.Build()
	log = baseLogger.Sugar()
}

func fmtMAC(mac []byte) string {
	if len(mac) != 6 {
		return "invalid_mac"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// summarizeFrame 解析以太网帧并返回一个易读的摘要
func summarizeFrame(frame []byte) string {
	if len(frame) < 14 {
		return fmt.Sprintf("Invalid Frame (len: %d)", len(frame))
	}

	dst := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", frame[0], frame[1], frame[2], frame[3], frame[4], frame[5])
	src := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", frame[6], frame[7], frame[8], frame[9], frame[10], frame[11])
	ethType := binary.BigEndian.Uint16(frame[12:14])

	proto := "Unknown"
	details := ""

	switch ethType {
	case 0x0806: // ARP
		proto = "ARP"
		if len(frame) >= 42 {
			op := binary.BigEndian.Uint16(frame[20:22])
			senderIP := net.IP(frame[28:32])
			targetIP := net.IP(frame[38:42])
			opStr := "Request"
			if op == 2 {
				opStr = "Reply"
			}
			details = fmt.Sprintf("[%s] %s -> %s", opStr, senderIP, targetIP)
		}
	case 0x0800: // IPv4
		proto = "IPv4"
		if len(frame) >= 34 {
			ipProto := frame[23]
			sIP := net.IP(frame[26:30])
			dIP := net.IP(frame[30:34])
			pName := fmt.Sprintf("Proto:%d", ipProto)
			if ipProto == 1 {
				pName = "ICMP"
			} else if ipProto == 6 {
				pName = "TCP"
			} else if ipProto == 17 {
				pName = "UDP"
			}
			details = fmt.Sprintf("[%s] %s -> %s", pName, sIP, dIP)
		}
	case 0x86dd: // IPv6
		proto = "IPv6"
	}

	return fmt.Sprintf("%s | %s -> %s | %s", proto, src, dst, details)
}

// ======================= 自动生成内存 TLS 证书 =======================
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"tapvpn-quic"}, // ALPN 标识
	}
}

// ======================= 流式帧扫描器 (适配 io.Reader/Writer) =======================
func writeStreamFrame(w io.Writer, frame []byte) error {
	length := len(frame)
	buf := make([]byte, 2+length)
	binary.BigEndian.PutUint16(buf[:2], uint16(length))
	copy(buf[2:], frame)
	
	_, err := w.Write(buf)
	return err
}

type FrameScanner struct {
	r   io.Reader
	buf []byte
}

func NewFrameScanner(r io.Reader) *FrameScanner {
	return &FrameScanner{
		r:   r,
		buf: make([]byte, 0, 65536),
	}
}

func (fs *FrameScanner) ReadFrame() ([]byte, error) {
	for {
		if len(fs.buf) >= 2 {
			length := int(binary.BigEndian.Uint16(fs.buf[:2]))
			if length > 0 && length < 1600 {
				if len(fs.buf) >= 2+length {
					frame := make([]byte, length)
					copy(frame, fs.buf[2:2+length])
					
					remaining := len(fs.buf) - (2 + length)
					copy(fs.buf, fs.buf[2+length:])
					fs.buf = fs.buf[:remaining]
					return frame, nil
				}
			} else {
				log.Warnf("[FrameScanner] CORRUPTION DETECTED: Invalid length %d. Dropping buffer.", length)
				fs.buf = fs.buf[:0]
			}
		}

		temp := make([]byte, 65536)
		n, err := fs.r.Read(temp)
		if err != nil {
			return nil, err
		}
		if n > 0 {
			fs.buf = append(fs.buf, temp[:n]...)
		}
	}
}

// ======================= 协议与配置 =======================
type HandshakeReq struct {
	PSK  string `json:"psk"`
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

type HandshakeResp struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
}

func main() {
	mode := flag.String("mode", "", "server or client")
	psk := flag.String("psk", "quic_secret", "Pre-shared key")
	tapName := flag.String("tap", "tap0", "Name of the TAP device")
	addr := flag.String("addr", "0.0.0.0:4000", "Server address")
	logLevel := flag.String("loglevel", "info", "Log level")

	v4cidr := flag.String("v4cidr", "10.0.0.0/24", "IPv4 CIDR block (Server only)")
	v6cidr := flag.String("v6cidr", "fd00::/64", "IPv6 CIDR block (Server only)")

	reqV4 := flag.String("req-v4", "", "Requested IPv4 (Client only)")
	reqV6 := flag.String("req-v6", "", "Requested IPv6 (Client only)")

	flag.Parse()
	initLogger(*logLevel)
	defer log.Sync()

	if *mode == "server" {
		startServer(*psk, *tapName, *addr, *v4cidr, *v6cidr)
	} else if *mode == "client" {
		startClient(*psk, *tapName, *addr, *reqV4, *reqV6)
	} else {
		fmt.Println("Usage: go run main.go -mode server|client")
		os.Exit(1)
	}
}

// ======================= VSwitch 虚拟交换机 =======================
type Port interface {
	ID() string
	WriteFrame(frame []byte) error
}

type macEntry struct {
	portID    string
	updatedAt time.Time
}

type VSwitch struct {
	mu       sync.RWMutex
	ports    map[string]Port
	macTable map[string]*macEntry
}

func NewVSwitch() *VSwitch {
	return &VSwitch{
		ports:    make(map[string]Port),
		macTable: make(map[string]*macEntry),
	}
}

func (vs *VSwitch) AddPort(p Port) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.ports[p.ID()] = p
	log.Infof("[VSwitch] Port UP: %s", p.ID())
}

func (vs *VSwitch) RemovePort(portID string) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	delete(vs.ports, portID)
	for mac, entry := range vs.macTable {
		if entry.portID == portID {
			delete(vs.macTable, mac)
		}
	}
	log.Infof("[VSwitch] Port DOWN: %s", portID)
}

func (vs *VSwitch) ProcessFrame(srcPortID string, frame []byte) {
	if len(frame) < 14 {
		return
	}
	dstMAC := frame[0:6]
	srcMAC := frame[6:12]
	strDstMAC := string(dstMAC)
	strSrcMAC := string(srcMAC)

	vs.mu.Lock()
	if _, exists := vs.macTable[strSrcMAC]; !exists {
		log.Debugf("[VSwitch] Learned NEW MAC %s on port %s", fmtMAC(srcMAC), srcPortID)
	}
	vs.macTable[strSrcMAC] = &macEntry{portID: srcPortID, updatedAt: time.Now()}

	isBUM := (dstMAC[0] & 1) == 1
	var targetPortID string
	if !isBUM {
		if entry, exists := vs.macTable[strDstMAC]; exists {
			targetPortID = entry.portID
		}
	}
	vs.mu.Unlock()

	if targetPortID != "" {
		if targetPortID != srcPortID {
			vs.sendToPort(targetPortID, frame)
		}
	} else {
		vs.flood(srcPortID, frame)
	}
}

func (vs *VSwitch) sendToPort(targetPortID string, frame []byte) {
	vs.mu.RLock()
	port, exists := vs.ports[targetPortID]
	vs.mu.RUnlock()
	if exists {
		port.WriteFrame(frame)
	}
}

func (vs *VSwitch) flood(excludePortID string, frame []byte) {
	vs.mu.RLock()
	var targets []Port
	for id, port := range vs.ports {
		if id != excludePortID {
			targets = append(targets, port)
		}
	}
	vs.mu.RUnlock()
	for _, port := range targets {
		port.WriteFrame(frame)
	}
}

// ======================= 异步端口 =======================
type AsyncPort struct {
	id     string
	ch     chan []byte
	writer func([]byte) error
	closed bool
}

func NewAsyncPort(id string, writer func([]byte) error) *AsyncPort {
	p := &AsyncPort{
		id:     id,
		ch:     make(chan []byte, 4096),
		writer: writer,
	}
	go p.run()
	return p
}

func (p *AsyncPort) ID() string { return p.id }

func (p *AsyncPort) WriteFrame(frame []byte) error {
	if p.closed {
		return nil
	}
	buf := make([]byte, len(frame))
	copy(buf, frame)
	select {
	case p.ch <- buf:
	default:
		log.Warnf("[AsyncPort %s] BACKPRESSURE! Queue full", p.id)
	}
	return nil
}

func (p *AsyncPort) run() {
	for frame := range p.ch {
		if err := p.writer(frame); err != nil {
			log.Debugf("[AsyncPort %s] Writer returned error: %v", p.id, err)
		}
	}
}

func (p *AsyncPort) Close() {
	p.closed = true
	close(p.ch)
}

// ======================= 服务端实现 =======================
type Server struct {
	psk     string
	v4Net   *net.IPNet
	v6Net   *net.IPNet
	usedV4  map[string]bool
	usedV6  map[string]bool
	mu      sync.Mutex
	tap     *water.Interface
	vswitch *VSwitch
}

func startServer(psk, tapName, addr, v4cidr, v6cidr string) {
	log.Infof("Starting QUIC server process...")
	_, v4net, _ := net.ParseCIDR(v4cidr)
	_, v6net, _ := net.ParseCIDR(v6cidr)

	srv := &Server{
		psk:     psk,
		v4Net:   v4net,
		v6Net:   v6net,
		usedV4:  make(map[string]bool),
		usedV6:  make(map[string]bool),
		vswitch: NewVSwitch(),
	}

	srvV4IP := getFirstIP(v4net)
	srvV6IP := getFirstIP(v6net)
	srv.usedV4[srvV4IP.String()] = true
	srv.usedV6[srvV6IP.String()] = true

	config := water.Config{DeviceType: water.TAP}
	config.Name = tapName
	tap, err := water.New(config)
	if err != nil {
		log.Fatalf("Server TAP error: %v", err)
	}
	srv.tap = tap

	if link, err := netlink.LinkByName(tapName); err == nil {
		v4Addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", srvV4IP.String(), maskSize(v4net.Mask)))
		netlink.AddrReplace(link, v4Addr)
		netlink.LinkSetUp(link)
		log.Infof("Server TAP configured: %s", v4Addr.String())
	}

	tapPortID := "TAP_LOCAL"
	tapPort := NewAsyncPort(tapPortID, func(b []byte) error {
		_, err := srv.tap.Write(b)
		return err
	})
	srv.vswitch.AddPort(tapPort)

	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := srv.tap.Read(buf)
			if err != nil {
				log.Fatalf("[Server Local] TAP Read error: %v", err)
			}
			frame := buf[:n]
			if len(frame) < 60 {
				padded := make([]byte, 60)
				copy(padded, frame)
				frame = padded
			}
			srv.vswitch.ProcessFrame(tapPortID, frame)
		}
	}()

	// ==================== 启动 QUIC 监听 ====================
	quicConfig := &quic.Config{
		KeepAlivePeriod: 10 * time.Second, // 保持连接活跃，支持完美的连接迁移
		MaxIdleTimeout:  5 * time.Minute,
	}

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), quicConfig)
	if err != nil {
		log.Fatalf("QUIC Listen error: %v", err)
	}
	log.Infof("VPN Server running and listening on %s (QUIC UDP)", addr)

	for {
		// 最新版 quic.ListenAddr 返回的 listener 拥有 Accept 结构体方法，并且直接返回 *quic.Conn 
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Warnf("QUIC Accept error: %v", err)
			continue
		}
		log.Infof("Accepted new QUIC connection from %s", conn.RemoteAddr().String())
		
		// 纯净调用：不加任何断言
		go func(c *quic.Conn) {
			stream, err := c.AcceptStream(context.Background()) // 直接返回 *quic.Stream
			if err != nil {
				log.Warnf("Failed to accept QUIC Stream: %v", err)
				return
			}
			srv.handleClient(c, stream)
		}(conn) 
	}
}

// 纯净声明：直接接收最新的结构体指针
func (s *Server) handleClient(conn *quic.Conn, stream *quic.Stream) {
	defer conn.CloseWithError(0, "Closed intentionally")
	clientID := conn.RemoteAddr().String()

	scanner := NewFrameScanner(stream)

	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	reqData, err := scanner.ReadFrame()
	if err != nil {
		log.Warnf("[%s] Handshake read error: %v", clientID, err)
		return
	}
	stream.SetReadDeadline(time.Time{})

	var req HandshakeReq
	if err := json.Unmarshal(reqData, &req); err != nil || req.PSK != s.psk {
		log.Warnf("[%s] PSK Mismatch! Connection rejected.", clientID)
		s.sendResp(stream, false, "Auth failed", "", "")
		return
	}

	v4ip, v6ip := s.assignIPs(req.IPv4, req.IPv6)

	defer func() {
		s.mu.Lock()
		delete(s.usedV4, v4ip)
		delete(s.usedV6, v6ip)
		s.mu.Unlock()
		s.vswitch.RemovePort(clientID)
	}()

	v4cidr := fmt.Sprintf("%s/%d", v4ip, maskSize(s.v4Net.Mask))
	v6cidr := fmt.Sprintf("%s/%d", v6ip, maskSize(s.v6Net.Mask))
	s.sendResp(stream, true, "OK", v4cidr, v6cidr)
	
	log.Infof("[%s] Handshake OK. Assigned: %s", clientID, v4cidr)

	clientPort := NewAsyncPort(clientID, func(b []byte) error {
		return writeStreamFrame(stream, b)
	})
	s.vswitch.AddPort(clientPort)
	defer clientPort.Close()

	for {
		frame, err := scanner.ReadFrame()
		if err != nil {
			log.Infof("[%s] QUIC Stream closed: %v", clientID, err)
			break
		}
		s.vswitch.ProcessFrame(clientID, frame)
	}
}

func (s *Server) assignIPs(reqV4, reqV6 string) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alloc := func(req string, netw *net.IPNet, used map[string]bool) string {
		parsed := net.ParseIP(req)
		if parsed != nil && netw.Contains(parsed) && !used[parsed.String()] {
			used[parsed.String()] = true
			return parsed.String()
		}
		ip := duplicateIP(netw.IP)
		for netw.Contains(ip) {
			ipStr := ip.String()
			if !used[ipStr] && ip[len(ip)-1] != 0 && ip[len(ip)-1] != 255 {
				used[ipStr] = true
				return ipStr
			}
			incrementIP(ip)
		}
		return ""
	}
	return alloc(reqV4, s.v4Net, s.usedV4), alloc(reqV6, s.v6Net, s.usedV6)
}

func (s *Server) sendResp(w io.Writer, ok bool, msg, v4, v6 string) {
	d, _ := json.Marshal(HandshakeResp{Success: ok, Message: msg, IPv4: v4, IPv6: v6})
	writeStreamFrame(w, d)
}

// ======================= 客户端实现 =======================
type Client struct {
	psk        string
	serverAddr string
	tapName    string
	reqV4      string
	reqV6      string
	tap        *water.Interface
}

func startClient(psk, tapName, addr, reqV4, reqV6 string) {
	log.Infof("Starting QUIC client process...")
	config := water.Config{DeviceType: water.TAP}
	config.Name = tapName
	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("Client TAP creation error: %v", err)
	}

	c := &Client{
		psk:        psk,
		serverAddr: addr,
		tapName:    tapName,
		reqV4:      reqV4,
		reqV6:      reqV6,
		tap:        iface,
	}

	for {
		err := c.dialAndServe()
		log.Warnf("Tunnel down: %v. Reconnecting in 3s...", err)
		time.Sleep(3 * time.Second)
	}
}

func (c *Client) dialAndServe() error {
	// ==================== QUIC 拨号 ====================
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,             // 忽略证书校验
		NextProtos:         []string{"tapvpn-quic"},
	}
	quicConfig := &quic.Config{
		KeepAlivePeriod: 10 * time.Second, // 支持连接迁移不断线
		MaxIdleTimeout:  5 * time.Minute,
	}

	log.Infof("Initiating QUIC dial to Server: %s", c.serverAddr)
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	// 最新版直接返回 *quic.Conn，干净清爽
	conn, err := quic.DialAddr(ctx, c.serverAddr, tlsConf, quicConfig)
	if err != nil {
		return fmt.Errorf("QUIC dial failed: %v", err)
	}
	defer conn.CloseWithError(0, "Client closed")
	
	log.Infof("QUIC tunnel established to %s. Connection Migration ready.", c.serverAddr)

	// 最新版直接返回 *quic.Stream，干净清爽
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open QUIC stream: %v", err)
	}

	scanner := NewFrameScanner(stream)

	// 握手
	req := HandshakeReq{PSK: c.psk, IPv4: c.reqV4, IPv6: c.reqV6}
	reqData, _ := json.Marshal(req)
	if err := writeStreamFrame(stream, reqData); err != nil {
		return fmt.Errorf("failed to send handshake: %v", err)
	}

	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	respData, err := scanner.ReadFrame()
	if err != nil {
		return fmt.Errorf("handshake read error: %v", err)
	}
	stream.SetReadDeadline(time.Time{})

	var resp HandshakeResp
	if err := json.Unmarshal(respData, &resp); err != nil || !resp.Success {
		return fmt.Errorf("handshake failed/rejected: %v", err)
	}

	log.Infof("Handshake OK! Assigned: %s", resp.IPv4)

	if err := c.setupInterface(resp.IPv4, resp.IPv6); err != nil {
		return fmt.Errorf("TAP interface setup failed: %v", err)
	}

	errChan := make(chan error, 2)

	// TAP -> QUIC Stream
	go func() {
		buf := make([]byte, 65536)
		frameIdx := 0
		for {
			rn, err := c.tap.Read(buf)
			if err != nil {
				log.Errorf("[Tunnel] TAP Read Error: %v", err)
				errChan <- err
				return
			}
			frameIdx++
			frame := buf[:rn]

			if len(frame) < 60 {
				padded := make([]byte, 60)
				copy(padded, frame)
				frame = padded
			}
			
			if err := writeStreamFrame(stream, frame); err != nil {
				log.Errorf("[Tx-#%d] QUIC Write Error: %v", frameIdx, err)
				errChan <- err
				return
			}
		}
	}()

	// QUIC Stream -> TAP
	go func() {
		frameIdx := 0
		for {
			frame, err := scanner.ReadFrame()
			if err != nil {
				log.Errorf("[Rx] QUIC Read Error: %v", err)
				errChan <- err
				return
			}
			frameIdx++
			
			summary := summarizeFrame(frame)
			log.Debugf("[Rx-#%d] Received from tunnel: %d bytes | %s", frameIdx, len(frame), summary)

			if _, err := c.tap.Write(frame); err != nil {
				log.Errorf("[Rx-#%d] TAP Write Error: %v", frameIdx, err)
				errChan <- err
				return
			}
		}
	}()

	log.Infof("QUIC Tunnel Data Plane is Active. Try switching Wi-Fi/Cellular to test Connection Migration!")
	return <-errChan
}

func (c *Client) setupInterface(v4cidr, v6cidr string) error {
	link, err := netlink.LinkByName(c.tapName)
	if err != nil {
		return err
	}

	if v4cidr != "/" && v4cidr != "" {
		if addrV4, err := netlink.ParseAddr(v4cidr); err == nil {
			netlink.AddrReplace(link, addrV4)
		}
	}
	if v6cidr != "/" && v6cidr != "" {
		if addrV6, err := netlink.ParseAddr(v6cidr); err == nil {
			netlink.AddrReplace(link, addrV6)
		}
	}
	return netlink.LinkSetUp(link)
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func duplicateIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func maskSize(m net.IPMask) int {
	ones, _ := m.Size()
	return ones
}

func getFirstIP(network *net.IPNet) net.IP {
	ip := duplicateIP(network.IP)
	incrementIP(ip)
	return ip
}