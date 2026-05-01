package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	mathrand.Seed(time.Now().UnixNano())
}

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

// ======================= 随机混淆生成器 =======================
func generatePadding(min, max int) string {
	length := mathrand.Intn(max-min+1) + min
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

// ======================= TLS 证书管理 (伪装 h3 ALPN) =======================
func getServerTLSConfig(certFile, keyFile string) *tls.Config {
	var cert tls.Certificate
	var err error

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load custom TLS pair: %v", err)
		}
		log.Infof("Loaded custom TLS certificate: %s", certFile)
	} else {
		log.Infof("No cert/key specified. Generating ephemeral memory certificate...")
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

		cert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			panic(err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3", "h3-29"}, // HTTP/3 伪装
	}
}

// ======================= 策略路由 (纯 Netlink 实现) =======================
func setupPolicyRouting(tapName string, mark int, gwV4, gwV6 string) error {
	if mark <= 0 {
		return nil
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("failed to find tap dev %s: %v", tapName, err)
	}

	setup := func(gwStr string, family int) {
		if gwStr == "" {
			return
		}
		gw := net.ParseIP(gwStr)

		rule := netlink.NewRule()
		rule.Mark = uint32(mark)
		rule.Table = mark
		rule.Family = family
		netlink.RuleDel(rule)
		if err := netlink.RuleAdd(rule); err != nil {
			log.Warnf("Failed to add rule for fwmark %d: %v", mark, err)
		}

		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       nil,
			Gw:        gw,
			Table:     mark,
		}
		if err := netlink.RouteReplace(route); err != nil {
			log.Warnf("Failed to replace route in table %d: %v", mark, err)
		}
	}

	setup(gwV4, netlink.FAMILY_V4)
	setup(gwV6, netlink.FAMILY_V6)
	log.Infof("🔀 Policy routing configured (fwmark: %d)", mark)
	return nil
}

func cleanPolicyRouting(tapName string, mark int, gwV4, gwV6 string) {
	if mark <= 0 {
		return
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return
	}

	cleanup := func(gwStr string, family int) {
		if gwStr == "" {
			return
		}
		gw := net.ParseIP(gwStr)

		rule := netlink.NewRule()
		rule.Mark = uint32(mark)
		rule.Table = mark
		rule.Family = family
		netlink.RuleDel(rule)

		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       nil,
			Gw:        gw,
			Table:     mark,
		}
		netlink.RouteDel(route)
	}

	cleanup(gwV4, netlink.FAMILY_V4)
	cleanup(gwV6, netlink.FAMILY_V6)
	log.Infof("🧹 Policy routing cleaned (fwmark: %d)", mark)
}

// ======================= 流式帧扫描器 =======================
func writeStreamFrame(w io.Writer, frame []byte) error {
	length := len(frame)
	buf := make([]byte, 2+length)
	binary.BigEndian.PutUint16(buf[:2], uint16(length))
	if length > 0 {
		copy(buf[2:], frame)
	}
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

			if length == 0 {
				remaining := len(fs.buf) - 2
				copy(fs.buf, fs.buf[2:])
				fs.buf = fs.buf[:remaining]
				continue
			}

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
				log.Warnf("[FrameScanner] CORRUPTION DETECTED: Invalid length %d.", length)
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
	PSK     string `json:"psk"`
	IPv4    string `json:"ipv4,omitempty"`
	IPv6    string `json:"ipv6,omitempty"`
	Padding string `json:"padding,omitempty"`
}

type HandshakeResp struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	IPv4    string `json:"ipv4"`
	IPv6    string `json:"ipv6"`
	GwV4    string `json:"gw_v4,omitempty"`
	GwV6    string `json:"gw_v6,omitempty"`
	Padding string `json:"padding,omitempty"`
}

func main() {
	mode := flag.String("mode", "", "server or client")
	psk := flag.String("psk", "quic_secret", "Pre-shared key")
	tapName := flag.String("tap", "tap0", "Name of the TAP device")
	addr := flag.String("addr", "0.0.0.0:4000", "Server address")
	logLevel := flag.String("loglevel", "info", "Log level")

	v4cidr := flag.String("v4cidr", "10.0.0.0/24", "IPv4 CIDR block (Server only)")
	v6cidr := flag.String("v6cidr", "fd00::/64", "IPv6 CIDR block (Server only)")
	certFile := flag.String("cert", "", "TLS Certificate file (Server only)")
	keyFile := flag.String("key", "", "TLS Key file (Server only)")

	reqV4 := flag.String("req-v4", "", "Requested IPv4 (Client only)")
	reqV6 := flag.String("req-v6", "", "Requested IPv6 (Client only)")
	sni := flag.String("sni", "www.cloudflare.com", "SNI for TLS (Client only)")
	insecure := flag.Bool("insecure", false, "Skip TLS verify (Client only)")
	certHash := flag.String("cert-sha256", "", "Verify server cert SHA256 (hex encoded) (Client only)")
	
	fwmark := flag.Int("fwmark", 0, "Enable policy routing with specified fwmark (e.g. 1911) (Client only)")

	flag.Parse()
	initLogger(*logLevel)
	defer log.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *mode == "server" {
		startServer(ctx, *psk, *tapName, *addr, *v4cidr, *v6cidr, *certFile, *keyFile)
	} else if *mode == "client" {
		startClient(ctx, *psk, *tapName, *addr, *reqV4, *reqV6, *sni, *insecure, *certHash, *fwmark)
	} else {
		fmt.Println("Usage: go run main.go -mode server|client [flags...]")
		os.Exit(1)
	}
	
	log.Info("Program exited gracefully.")
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
	log.Debugf("[VSwitch] Port UP: %s", p.ID())
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
	log.Debugf("[VSwitch] Port DOWN: %s", portID)
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
	ctx    context.Context
	cancel context.CancelFunc
}

func NewAsyncPort(ctx context.Context, id string, writer func([]byte) error) *AsyncPort {
	pCtx, pCancel := context.WithCancel(ctx)
	p := &AsyncPort{
		id:     id,
		ch:     make(chan []byte, 4096),
		writer: writer,
		ctx:    pCtx,
		cancel: pCancel,
	}
	go p.run()
	return p
}

func (p *AsyncPort) ID() string { return p.id }

func (p *AsyncPort) WriteFrame(frame []byte) error {
	select {
	case <-p.ctx.Done():
		return fmt.Errorf("port %s closed", p.id)
	default:
	}

	var buf []byte
	if frame != nil {
		buf = make([]byte, len(frame))
		copy(buf, frame)
	}
	select {
	case p.ch <- buf:
	default:
		log.Warnf("[AsyncPort %s] BACKPRESSURE! Queue full", p.id)
	}
	return nil
}

func (p *AsyncPort) run() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case frame := <-p.ch:
			if err := p.writer(frame); err != nil {
				log.Debugf("[AsyncPort %s] Writer returned error: %v", p.id, err)
			}
		}
	}
}

func (p *AsyncPort) Close() {
	p.cancel()
}

// ======================= 服务端实现 =======================
type Server struct {
	psk     string
	v4Net   *net.IPNet
	v6Net   *net.IPNet
	v4Gw    string 
	v6Gw    string 
	usedV4  map[string]bool
	usedV6  map[string]bool
	mu      sync.Mutex
	tap     *water.Interface
	vswitch *VSwitch
}

func startServer(ctx context.Context, psk, tapName, addr, v4cidr, v6cidr, certFile, keyFile string) {
	log.Infof("Starting QUIC server process... (HTTP/3 Camouflage Active)")
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
	srv.v4Gw = srvV4IP.String()
	srv.v6Gw = srvV6IP.String()
	
	srv.usedV4[srv.v4Gw] = true
	srv.usedV6[srv.v6Gw] = true

	config := water.Config{DeviceType: water.TAP}
	config.Name = tapName
	tap, err := water.New(config)
	if err != nil {
		log.Fatalf("Server TAP error: %v", err)
	}
	srv.tap = tap

	if link, err := netlink.LinkByName(tapName); err == nil {
		// 服务端同时配置 IPv4 和 IPv6 地址
		v4Addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", srv.v4Gw, maskSize(v4net.Mask)))
		netlink.AddrReplace(link, v4Addr)

		v6Addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", srv.v6Gw, maskSize(v6net.Mask)))
		netlink.AddrReplace(link, v6Addr)

		netlink.LinkSetUp(link)
		log.Infof("Server TAP configured: IPv4=%s, IPv6=%s", v4Addr.String(), v6Addr.String())
	} else {
		log.Errorf("Failed to configure Server TAP interface: %v", err)
	}

	go func() {
		<-ctx.Done()
		log.Info("Context canceled, closing TAP interface to unblock listeners...")
		srv.tap.Close()
	}()

	tapPortID := "TAP_LOCAL"
	tapPort := NewAsyncPort(ctx, tapPortID, func(b []byte) error {
		if len(b) > 0 {
			_, err := srv.tap.Write(b)
			return err
		}
		return nil
	})
	srv.vswitch.AddPort(tapPort)

	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := srv.tap.Read(buf)
				if err != nil {
					if ctx.Err() != nil { return }
					log.Errorf("[Server Local] TAP Read error: %v", err)
					return
				}
				frame := buf[:n]
				if len(frame) < 60 {
					padded := make([]byte, 60)
					copy(padded, frame)
					frame = padded
				}
				srv.vswitch.ProcessFrame(tapPortID, frame)
			}
		}
	}()

	quicConfig := &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  30 * time.Second, // 大幅缩短假死探测时间
	}

	tlsConfig := getServerTLSConfig(certFile, keyFile)
	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("QUIC Listen error: %v", err)
	}
	log.Infof("VPN Server listening on %s (Looks like standard HTTP/3 traffic)", addr)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				log.Info("Server listener closed by context.")
				break
			}
			log.Warnf("QUIC Accept error: %v", err)
			continue
		}
		
		go func(c *quic.Conn) {
			stream, err := c.AcceptStream(ctx)
			if err != nil {
				log.Debugf("Failed to accept QUIC Stream: %v", err)
				return
			}
			srv.handleClient(ctx, c, stream)
		}(conn)
	}
}

func (s *Server) handleClient(parentCtx context.Context, conn *quic.Conn, stream *quic.Stream) {
	connCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	defer conn.CloseWithError(0, "Closed intentionally")

	clientID := conn.RemoteAddr().String()
	scanner := NewFrameScanner(stream)

	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	reqData, err := scanner.ReadFrame()
	if err != nil {
		log.Debugf("[%s] Stream read error: %v", clientID, err)
		return
	}
	stream.SetReadDeadline(time.Time{})

	var req HandshakeReq
	if err := json.Unmarshal(reqData, &req); err != nil || req.PSK != s.psk {
		log.Warnf("[%s] Auth failed or invalid request. Dropping silently.", clientID)
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
	
	log.Infof("[%s] Tunnel established. Assigned V4: %s | V6: %s", clientID, v4cidr, v6cidr)

	clientPort := NewAsyncPort(connCtx, clientID, func(b []byte) error {
		return writeStreamFrame(stream, b)
	})
	s.vswitch.AddPort(clientPort)
	defer clientPort.Close()

	go func() {
		for {
			jitterDelay := time.Duration(mathrand.Intn(3000)+4000) * time.Millisecond
			select {
			case <-connCtx.Done():
				return
			case <-time.After(jitterDelay):
				clientPort.WriteFrame(nil) // 心跳帧
			}
		}
	}()

	for {
		select {
		case <-connCtx.Done():
			return
		default:
			frame, err := scanner.ReadFrame()
			if err != nil {
				log.Debugf("[%s] Tunnel stream closed: %v", clientID, err)
				return
			}
			s.vswitch.ProcessFrame(clientID, frame)
		}
	}
}

func (s *Server) assignIPs(reqV4, reqV6 string) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	alloc := func(req string, netw *net.IPNet, used map[string]bool) string {
		req = strings.Split(req, "/")[0]
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

func (s *Server) sendResp(w io.Writer, ok bool, msg, v4cidr, v6cidr string) {
	d, _ := json.Marshal(HandshakeResp{
		Success: ok, 
		Message: msg, 
		IPv4:    v4cidr, 
		IPv6:    v6cidr,
		GwV4:    s.v4Gw, 
		GwV6:    s.v6Gw,
		Padding: generatePadding(100, 500), 
	})
	writeStreamFrame(w, d)
}

// ======================= 客户端实现 =======================
type Client struct {
	psk        string
	serverAddr string
	tapName    string
	reqV4      string
	reqV6      string
	sni        string
	insecure   bool
	certHash   string
	fwmark     int
	tap        *water.Interface
	tapTxChan  chan []byte // 全局发送通道，防止协程泄漏
}

func startClient(ctx context.Context, psk, tapName, addr, reqV4, reqV6, sni string, insecure bool, certHash string, fwmark int) {
	log.Infof("Starting QUIC client process... (HTTP/3 Camouflage Active)")
	config := water.Config{DeviceType: water.TAP}
	config.Name = tapName
	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("Client TAP creation error: %v", err)
	}

	go func() {
		<-ctx.Done()
		log.Info("Context canceled, closing local TAP interface...")
		iface.Close()
	}()

	c := &Client{
		psk:        psk,
		serverAddr: addr,
		tapName:    tapName,
		reqV4:      reqV4,
		reqV6:      reqV6,
		sni:        sni,
		insecure:   insecure,
		certHash:   certHash,
		fwmark:     fwmark,
		tap:        iface,
		tapTxChan:  make(chan []byte, 4096),
	}

	// 唯一常驻读取协程，断线重连也不会泄漏
	go func() {
		buf := make([]byte, 65536)
		for {
			rn, err := iface.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Errorf("[Tunnel] TAP Read Error: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}
			frame := make([]byte, rn)
			copy(frame, buf[:rn])

			if len(frame) < 60 {
				padded := make([]byte, 60)
				copy(padded, frame)
				frame = padded
			}

			select {
			case <-ctx.Done():
				return
			case c.tapTxChan <- frame:
			default:
				// 背压防爆
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			log.Info("Client shutdown loop finished.")
			return
		default:
			err := c.dialAndServe(ctx)
			log.Warnf("Tunnel down: %v. Reconnecting in 3s...", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (c *Client) dialAndServe(parentCtx context.Context) error {
	runCtx, runCancel := context.WithCancel(parentCtx)
	defer runCancel()

	tlsConf := &tls.Config{
		ServerName:         c.sni,
		InsecureSkipVerify: c.insecure,
		NextProtos:         []string{"h3"},
	}

	if c.certHash != "" {
		tlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates provided by server")
			}
			hash := sha256.Sum256(rawCerts[0])
			hashStr := hex.EncodeToString(hash[:])
			if hashStr != c.certHash {
				return fmt.Errorf("cert SHA-256 mismatch. Expected %s, got %s", c.certHash, hashStr)
			}
			return nil
		}
	}

	quicConfig := &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  30 * time.Second,
	}

	log.Infof("Initiating connection to Server: %s (SNI: %s)", c.serverAddr, c.sni)
	
	dialCtx, dialCancel := context.WithTimeout(runCtx, 5*time.Second)
	conn, err := quic.DialAddr(dialCtx, c.serverAddr, tlsConf, quicConfig)
	dialCancel()
	
	if err != nil {
		return fmt.Errorf("QUIC dial failed: %v", err)
	}
	defer conn.CloseWithError(0, "Client closed")
	
	log.Infof("Encrypted transport established to %s.", c.serverAddr)

	stream, err := conn.OpenStreamSync(runCtx)
	if err != nil {
		return fmt.Errorf("failed to open QUIC stream: %v", err)
	}

	scanner := NewFrameScanner(stream)

	req := HandshakeReq{
		PSK:     c.psk, 
		IPv4:    c.reqV4, 
		IPv6:    c.reqV6,
		Padding: generatePadding(100, 500), 
	}
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

	log.Infof("Tunnel negotiated! IPv4: %s (GW: %s) | IPv6: %s (GW: %s)", resp.IPv4, resp.GwV4, resp.IPv6, resp.GwV6)

	if err := c.setupInterface(resp.IPv4, resp.IPv6); err != nil {
		return fmt.Errorf("TAP interface setup failed: %v", err)
	}

	if err := setupPolicyRouting(c.tapName, c.fwmark, resp.GwV4, resp.GwV6); err != nil {
		log.Warnf("Policy routing setup failed: %v", err)
	}
	defer cleanPolicyRouting(c.tapName, c.fwmark, resp.GwV4, resp.GwV6)

	errChan := make(chan error, 2)

	go func() {
		for {
			jitterDelay := time.Duration(mathrand.Intn(3000)+4000) * time.Millisecond
			
			select {
			case <-runCtx.Done():
				return
			case frame := <-c.tapTxChan: // 从全局缓冲池取网卡包发送
				if err := writeStreamFrame(stream, frame); err != nil {
					log.Debugf("[Tx] QUIC Write Error: %v", err)
					errChan <- err
					return
				}
			case <-time.After(jitterDelay):
				if err := writeStreamFrame(stream, nil); err != nil {
					log.Debugf("[Tx] Keep-alive Write Error: %v", err)
					errChan <- err
					return
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-runCtx.Done():
				return
			default:
				frame, err := scanner.ReadFrame()
				if err != nil {
					log.Debugf("[Rx] Tunnel stream closed: %v", err)
					errChan <- err
					return
				}
				
				if _, err := c.tap.Write(frame); err != nil {
					log.Errorf("[Rx] TAP Write Error: %v", err)
					errChan <- err
					return
				}
			}
		}
	}()

	log.Infof("QUIC Tunnel Data Plane Active.")
	
	select {
	case err := <-errChan:
		return err
	case <-runCtx.Done():
		return nil
	}
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