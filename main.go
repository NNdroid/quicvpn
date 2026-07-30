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

// summarizeFrame 用于数据包以太网帧摘要解析与日志分析
func summarizeFrame(frame []byte) string {
	if len(frame) < 14 {
		return fmt.Sprintf("Invalid Frame (len: %d)", len(frame))
	}
	dstMAC := frame[0:6]
	srcMAC := frame[6:12]
	etherType := binary.BigEndian.Uint16(frame[12:14])

	if etherType == 0x0800 && len(frame) >= 34 { // IPv4
		protoNum := frame[23]
		srcIP := net.IP(frame[26:30]).String()
		dstIP := net.IP(frame[30:34]).String()

		protoStr := fmt.Sprintf("PROTO-%d", protoNum)
		switch protoNum {
		case 1:
			protoStr = "ICMP"
		case 6:
			protoStr = "TCP"
		case 17:
			protoStr = "UDP"
		}

		return fmt.Sprintf("IPv4 | %s -> %s | [%s] %s -> %s",
			fmtMAC(srcMAC), fmtMAC(dstMAC), protoStr, srcIP, dstIP)
	}

	if etherType == 0x86DD && len(frame) >= 54 { // IPv6
		srcIP := net.IP(frame[22:38]).String()
		dstIP := net.IP(frame[38:54]).String()
		protoNum := frame[20]
		return fmt.Sprintf("IPv6 | %s -> %s | [NextHeader-%s] %s -> %s",
			fmtMAC(srcMAC), fmtMAC(dstMAC), protoStrFromNum(protoNum), srcIP, dstIP)
	}

	return fmt.Sprintf("Ethernet (Type: 0x%04x) | %s -> %s | len: %d",
		etherType, fmtMAC(srcMAC), fmtMAC(dstMAC), len(frame))
}

func protoStrFromNum(n byte) string {
	switch n {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("PROTO-%d", n)
	}
}

// ======================= 内存池优化 (sync.Pool) =======================
var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, 65536)
		return &b
	},
}

func getFrame() []byte {
	ptr := framePool.Get().(*[]byte)
	return (*ptr)[:65536]
}

func putFrame(b []byte) {
	if cap(b) >= 1500 && cap(b) <= 65536 {
		ptr := (*[]byte)(&b)
		framePool.Put(ptr)
	}
}

// ======================= 底层 UDP 套接字 8MB 内核 Tuning =======================
func listenUDPWithBuffer(addrStr string, bufSize int) (*net.UDPConn, error) {
	laddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	if bufSize > 0 {
		_ = conn.SetReadBuffer(bufSize)
		_ = conn.SetWriteBuffer(bufSize)
	}
	return conn, nil
}

// ======================= 动态流量特征混淆引擎 =======================
func buildPaddedFrame(buf []byte, rn int, mode string, step int, maxMTU int) []byte {
	if mode == "off" || rn >= maxMTU {
		frame := getFrame()[:rn]
		copy(frame, buf[:rn])
		return frame
	}

	targetLen := rn
	switch mode {
	case "block":
		if step <= 0 {
			step = 128
		}
		targetLen = ((rn + step - 1) / step) * step
		if targetLen > maxMTU {
			targetLen = maxMTU
		}
	case "mtu":
		if maxMTU > rn {
			targetLen = maxMTU
		}
	case "random":
		jitter := mathrand.Intn(225) + 32
		targetLen = rn + jitter
		if targetLen > maxMTU {
			targetLen = maxMTU
		}
	default:
		if rn < 600 {
			targetLen = mathrand.Intn(301) + 600
		} else if rn <= 900 {
			targetLen = rn + mathrand.Intn(193) + 64
		}
		if targetLen > maxMTU {
			targetLen = maxMTU
		}
	}

	if targetLen < rn {
		targetLen = rn
	}

	frame := getFrame()[:targetLen]
	copy(frame, buf[:rn])

	if targetLen > rn {
		clear(frame[rn:targetLen])
	}

	return frame
}

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
		NextProtos:   []string{"h3", "h3-29"},
	}
}

// ======================= 高性能 O(1) 流式帧扫描器 =======================
func writeStreamFrame(w io.Writer, frame []byte) error {
	length := len(frame)

	streamBuf := getFrame()
	defer putFrame(streamBuf)

	if 2+length > cap(streamBuf) {
		streamBuf = make([]byte, 2+length)
	} else {
		streamBuf = streamBuf[:2+length]
	}

	binary.BigEndian.PutUint16(streamBuf[:2], uint16(length))
	if length > 0 {
		copy(streamBuf[2:], frame)
	}

	_, err := w.Write(streamBuf)
	return err
}

type FrameScanner struct {
	r   io.Reader
	buf []byte
	off int
}

func NewFrameScanner(r io.Reader) *FrameScanner {
	return &FrameScanner{
		r:   r,
		buf: make([]byte, 0, 65536),
		off: 0,
	}
}

func (fs *FrameScanner) ReadFrame() ([]byte, error) {
	for {
		avail := len(fs.buf) - fs.off
		if avail >= 2 {
			length := int(binary.BigEndian.Uint16(fs.buf[fs.off : fs.off+2]))

			if length == 0 {
				fs.off += 2
				continue
			}

			if length > 0 && length < 65000 {
				if avail >= 2+length {
					frame := getFrame()[:length]
					copy(frame, fs.buf[fs.off+2:fs.off+2+length])
					fs.off += 2 + length
					return frame, nil
				}
			} else {
				log.Warnf("[FrameScanner] CORRUPTION DETECTED: Invalid length %d.", length)
				fs.off = 0
				fs.buf = fs.buf[:0]
			}
		}

		if fs.off > 0 {
			remaining := len(fs.buf) - fs.off
			if remaining > 0 {
				copy(fs.buf[0:], fs.buf[fs.off:fs.off+remaining])
			}
			fs.buf = fs.buf[:remaining]
			fs.off = 0
		}

		temp := getFrame()
		n, err := fs.r.Read(temp)
		if n > 0 {
			fs.buf = append(fs.buf, temp[:n]...)
		}
		putFrame(temp)

		if err != nil {
			return nil, err
		}
	}
}

func camouflageProbe(stream *quic.Stream) {
	defer stream.Close()
	junkBuf := getFrame()
	defer putFrame(junkBuf)

	deadline := time.Now().Add(10 * time.Second)
	stream.SetReadDeadline(deadline)

	for {
		_, err := stream.Read(junkBuf)
		if err != nil {
			return
		}

		time.Sleep(time.Duration(mathrand.Intn(150)+50) * time.Millisecond)

		fakePayloadLen := mathrand.Intn(300) + 100
		fakeFrame := getFrame()[:fakePayloadLen+2]

		fakeFrame[0] = 0x00
		fakeFrame[1] = byte(fakePayloadLen)
		rand.Read(fakeFrame[2:])

		stream.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err = stream.Write(fakeFrame)
		putFrame(fakeFrame)
		if err != nil {
			return
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

var version = "dev"

func main() {
	showVersion := flag.Bool("version", false, "Show version information and exit")
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

	// 性能、特征混淆、FEC、多连接 Bonding、8MB UDP Socket 及抗 AI 时序 Flag
	paddingMode := flag.String("padding-mode", "block", "Padding mode: block, mtu, random, off")
	paddingStep := flag.Int("padding-step", 128, "Block padding step size in bytes")
	mtu := flag.Int("mtu", 1420, "Tunnel MTU size")
	useDatagram := flag.Bool("datagram", true, "Enable QUIC Datagram mode for ultra performance")
	conns := flag.Int("conns", 1, "Number of parallel QUIC connections for load balancing (Client only)")
	fecData := flag.Int("fec-data", 0, "FEC data shards (e.g. 10, 0 to disable)")
	fecParity := flag.Int("fec-parity", 0, "FEC parity shards (e.g. 2, 0 to disable)")
	soBufSize := flag.Int("so-buf", 8388608, "UDP Socket SO_RCVBUF / SO_SNDBUF size in bytes (default 8MB)")
	enableTimingShaping := flag.Bool("timing-shaping", true, "Enable microsecond Poisson timing shaping to bypass AI traffic classifiers")

	flag.Parse()

	if *showVersion {
		fmt.Printf("quicvpn version %s\n", version)
		os.Exit(0)
	}
	initLogger(*logLevel)
	defer log.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	shaper := NewTimingShaper(*enableTimingShaping, 50)

	if *mode == "server" {
		startServer(ctx, *psk, *tapName, *addr, *v4cidr, *v6cidr, *certFile, *keyFile, *paddingMode, *paddingStep, *mtu, *useDatagram, *fecData, *fecParity, *soBufSize, shaper)
	} else if *mode == "client" {
		startClient(ctx, *psk, *tapName, *addr, *reqV4, *reqV6, *sni, *insecure, *certHash, *fwmark, *paddingMode, *paddingStep, *mtu, *useDatagram, *conns, *fecData, *fecParity, *soBufSize, shaper)
	} else {
		fmt.Println("Usage: go run main.go -mode server|client [flags...]")
		os.Exit(1)
	}

	log.Info("Program exited gracefully.")
}

// ======================= VSwitch 虚拟交换机 (0内存分配 + 读写锁优化) =======================
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
	macTable map[[6]byte]macEntry
}

func NewVSwitch() *VSwitch {
	return &VSwitch{
		ports:    make(map[string]Port),
		macTable: make(map[[6]byte]macEntry),
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
	var dstMAC, srcMAC [6]byte
	copy(dstMAC[:], frame[0:6])
	copy(srcMAC[:], frame[6:12])

	now := time.Now()

	vs.mu.RLock()
	entry, srcExists := vs.macTable[srcMAC]
	vs.mu.RUnlock()

	if !srcExists || entry.portID != srcPortID || now.Sub(entry.updatedAt) > 10*time.Second {
		vs.mu.Lock()
		if _, exists := vs.macTable[srcMAC]; !exists {
			log.Debugf("[VSwitch] Learned NEW MAC %s on port %s", fmtMAC(srcMAC[:]), srcPortID)
		}
		vs.macTable[srcMAC] = macEntry{portID: srcPortID, updatedAt: now}
		vs.mu.Unlock()
	}

	isBUM := (dstMAC[0] & 1) == 1
	var targetPortID string
	if !isBUM {
		vs.mu.RLock()
		if dstEntry, dstExists := vs.macTable[dstMAC]; dstExists {
			targetPortID = dstEntry.portID
		}
		vs.mu.RUnlock()
	}

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

// ======================= 异步端口 (支持 Ring-Batching 批量刷新) =======================
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
		buf = getFrame()[:len(frame)]
		copy(buf, frame)
	}

	select {
	case p.ch <- buf:
	default:
		log.Warnf("[AsyncPort %s] BACKPRESSURE! Queue full, dropping frame.", p.id)
		if buf != nil {
			putFrame(buf)
		}
	}
	return nil
}

func (p *AsyncPort) run() {
	batch := make([][]byte, 0, 64)
	for {
		select {
		case <-p.ctx.Done():
			return
		case frame := <-p.ch:
			batch = append(batch, frame)

		drainLoop:
			for len(batch) < 64 {
				select {
				case f := <-p.ch:
					batch = append(batch, f)
				default:
					break drainLoop
				}
			}

			for _, f := range batch {
				if err := p.writer(f); err != nil {
					log.Debugf("[AsyncPort %s] Writer returned error: %v", p.id, err)
				}
				if f != nil {
					putFrame(f)
				}
			}
			batch = batch[:0]
		}
	}
}

func (p *AsyncPort) Close() {
	p.cancel()
}

// ======================= 服务端实现 =======================
type Server struct {
	psk         string
	v4Net       *net.IPNet
	v6Net       *net.IPNet
	v4Gw        string
	v6Gw        string
	usedV4      map[string]bool
	usedV6      map[string]bool
	mu          sync.Mutex
	tap         io.ReadWriteCloser
	vswitch     *VSwitch
	paddingMode string
	paddingStep int
	mtu         int
	useDatagram bool
	fecData     int
	fecParity   int
	soBufSize   int
	shaper      *TimingShaper
	sessions    map[string]*ServerSession
}

func startServer(ctx context.Context, psk, tapName, addr, v4cidr, v6cidr, certFile, keyFile, paddingMode string, paddingStep, mtu int, useDatagram bool, fecData, fecParity, soBufSize int, shaper *TimingShaper) {
	log.Infof("Starting QUIC server process... (HTTP/3 Camouflage, Padding: %s, FEC: %d:%d, SO_BUF: %dMB Active)", paddingMode, fecData, fecParity, soBufSize/(1024*1024))
	_, v4net, _ := net.ParseCIDR(v4cidr)
	_, v6net, _ := net.ParseCIDR(v6cidr)

	srv := &Server{
		psk:         psk,
		v4Net:       v4net,
		v6Net:       v6net,
		usedV4:      make(map[string]bool),
		usedV6:      make(map[string]bool),
		vswitch:     NewVSwitch(),
		paddingMode: paddingMode,
		paddingStep: paddingStep,
		mtu:         mtu,
		useDatagram: useDatagram,
		fecData:     fecData,
		fecParity:   fecParity,
		soBufSize:   soBufSize,
		shaper:      shaper,
		sessions:    make(map[string]*ServerSession),
	}

	srvV4IP := getFirstIP(v4net)
	srvV6IP := getFirstIP(v6net)
	srv.v4Gw = srvV4IP.String()
	srv.v6Gw = srvV6IP.String()

	srv.usedV4[srv.v4Gw] = true
	srv.usedV6[srv.v6Gw] = true

	tap, actualTapName, err := createTAPDevice(tapName)
	if err != nil {
		log.Fatalf("Server TAP error: %v", err)
	}
	srv.tap = tap

	if err := configureTAPInterface(actualTapName, srv.v4Gw, srv.v6Gw, v4net, v6net); err != nil {
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

	// 服务端本地 TAP 读取循环
	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				rn, err := srv.tap.Read(buf)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					log.Errorf("[Server Local] TAP Read error: %v", err)
					return
				}

				frame := buildPaddedFrame(buf, rn, srv.paddingMode, srv.paddingStep, srv.mtu)
				srv.vswitch.ProcessFrame(tapPortID, frame)
				putFrame(frame)
			}
		}
	}()

	quicConfig := &quic.Config{
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  30 * time.Second,
		EnableDatagrams: useDatagram,
	}

	tlsConfig := getServerTLSConfig(certFile, keyFile)

	udpConn, err := listenUDPWithBuffer(addr, soBufSize)
	if err != nil {
		log.Fatalf("Failed to listen UDP with buffer tuning: %v", err)
	}

	listener, err := quic.Listen(udpConn, tlsConfig, quicConfig)
	if err != nil {
		log.Fatalf("QUIC Listen error: %v", err)
	}
	log.Infof("VPN Server listening on %s (8MB SO_BUF Tuned & HTTP/3 Camouflaged)", addr)

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
			srv.handleClientConn(ctx, c, stream)
		}(conn)
	}
}

func (s *Server) handleClientConn(parentCtx context.Context, conn *quic.Conn, stream *quic.Stream) {
	clientID := conn.RemoteAddr().String()
	scanner := NewFrameScanner(stream)

	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	reqData, err := scanner.ReadFrame()
	if err != nil {
		log.Debugf("[%s] Stream read error or probe detected: %v", clientID, err)
		camouflageProbe(stream)
		return
	}
	stream.SetReadDeadline(time.Time{})

	var req HandshakeReq
	if err := json.Unmarshal(reqData, &req); err != nil || req.PSK != s.psk {
		log.Warnf("[%s] Auth failed. Entering camouflage tarpit.", clientID)
		putFrame(reqData)
		camouflageProbe(stream)
		return
	}
	putFrame(reqData)

	v4ip, v6ip := s.assignIPs(req.IPv4, req.IPv6)

	v4cidr := fmt.Sprintf("%s/%d", v4ip, maskSize(s.v4Net.Mask))
	v6cidr := fmt.Sprintf("%s/%d", v6ip, maskSize(s.v6Net.Mask))

	s.sendResp(stream, true, "OK", v4cidr, v6cidr)

	log.Infof("[%s] Tunnel connection established. Assigned V4: %s | V6: %s", clientID, v4cidr, v6cidr)

	s.mu.Lock()
	sess, exists := s.sessions[clientID]
	if !exists {
		sess = NewServerSession(parentCtx, clientID)
		s.sessions[clientID] = sess

		fecEnc, _ := NewFECEncoder(s.fecData, s.fecParity)
		clientPort := NewAsyncPort(sess.ctx, clientID, func(b []byte) error {
			if len(b) == 0 {
				return sess.Send(b, s.useDatagram)
			}
			s.shaper.Delay() // 抗 AI 时序塑形
			if fecEnc != nil {
				encodedShards := fecEnc.Input(b)
				for _, shard := range encodedShards {
					_ = sess.Send(shard, s.useDatagram)
					putFrame(shard)
				}
				return nil
			}
			return sess.Send(b, s.useDatagram)
		})
		s.vswitch.AddPort(clientPort)

		go func() {
			<-sess.ctx.Done()
			s.mu.Lock()
			delete(s.sessions, clientID)
			s.usedV4[v4ip] = false
			s.usedV6[v6ip] = false
			s.mu.Unlock()
			s.vswitch.RemovePort(clientID)
		}()
	}
	sess.AddConn(conn, stream)
	s.mu.Unlock()

	fecDec := NewFECDecoder()

	// Datagram 接收处理协程
	if s.useDatagram {
		go func() {
			for {
				data, err := conn.ReceiveDatagram(sess.ctx)
				if err != nil {
					return
				}
				if len(data) > 0 {
					frames := fecDec.Input(data)
					for _, frame := range frames {
						s.vswitch.ProcessFrame(clientID, frame)
						putFrame(frame)
					}
				}
			}
		}()
	}

	for {
		select {
		case <-sess.ctx.Done():
			return
		default:
			pkt, err := scanner.ReadFrame()
			if err != nil {
				return
			}
			frames := fecDec.Input(pkt)
			putFrame(pkt)
			for _, frame := range frames {
				s.vswitch.ProcessFrame(clientID, frame)
				putFrame(frame)
			}
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
	psk         string
	serverAddr  string
	tapName     string
	reqV4       string
	reqV6       string
	sni         string
	insecure    bool
	certHash    string
	fwmark      int
	tap         io.ReadWriteCloser
	tapTxChan   chan []byte
	paddingMode string
	paddingStep int
	mtu         int
	useDatagram bool
	numConns    int
	fecData     int
	fecParity   int
	soBufSize   int
	shaper      *TimingShaper
}

func startClient(ctx context.Context, psk, tapName, addr, reqV4, reqV6, sni string, insecure bool, certHash string, fwmark int, paddingMode string, paddingStep, mtu int, useDatagram bool, numConns, fecData, fecParity, soBufSize int, shaper *TimingShaper) {
	log.Infof("Starting QUIC client process... (HTTP/3 Camouflage, Padding: %s, Conns: %d, FEC: %d:%d, SO_BUF: %dMB Active)", paddingMode, numConns, fecData, fecParity, soBufSize/(1024*1024))
	iface, actualTapName, err := createTAPDevice(tapName)
	if err != nil {
		log.Fatalf("Client TAP creation error: %v", err)
	}

	go func() {
		<-ctx.Done()
		log.Info("Context canceled, closing local TAP interface...")
		iface.Close()
	}()

	c := &Client{
		psk:         psk,
		serverAddr:  addr,
		tapName:     actualTapName,
		reqV4:       reqV4,
		reqV6:       reqV6,
		sni:         sni,
		insecure:    insecure,
		certHash:    certHash,
		fwmark:      fwmark,
		tap:         iface,
		tapTxChan:   make(chan []byte, 4096),
		paddingMode: paddingMode,
		paddingStep: paddingStep,
		mtu:         mtu,
		useDatagram: useDatagram,
		numConns:    numConns,
		fecData:     fecData,
		fecParity:   fecParity,
		soBufSize:   soBufSize,
		shaper:      shaper,
	}

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

			frame := buildPaddedFrame(buf, rn, c.paddingMode, c.paddingStep, c.mtu)

			select {
			case <-ctx.Done():
				putFrame(frame)
				return
			case c.tapTxChan <- frame:
			default:
				putFrame(frame)
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
		EnableDatagrams: c.useDatagram,
	}

	numConns := c.numConns
	if numConns <= 0 {
		numConns = 1
	}

	pool := NewClientConnPool()
	defer pool.Close()

	var firstResp HandshakeResp

	for i := 0; i < numConns; i++ {
		udpConn, err := listenUDPWithBuffer("0.0.0.0:0", c.soBufSize)
		if err != nil {
			return fmt.Errorf("failed to listen UDP for client conn #%d: %v", i+1, err)
		}

		remoteAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
		if err != nil {
			udpConn.Close()
			return fmt.Errorf("failed to resolve server addr: %v", err)
		}

		dialCtx, dialCancel := context.WithTimeout(runCtx, 5*time.Second)
		conn, err := quic.Dial(dialCtx, udpConn, remoteAddr, tlsConf, quicConfig)
		dialCancel()

		if err != nil {
			udpConn.Close()
			return fmt.Errorf("QUIC dial failed for conn #%d: %v", i+1, err)
		}

		stream, err := conn.OpenStreamSync(runCtx)
		if err != nil {
			conn.CloseWithError(0, "Stream open error")
			return fmt.Errorf("failed to open QUIC stream #%d: %v", i+1, err)
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
			conn.CloseWithError(0, "Handshake write error")
			return fmt.Errorf("failed to send handshake #%d: %v", i+1, err)
		}

		stream.SetReadDeadline(time.Now().Add(5 * time.Second))
		respData, err := scanner.ReadFrame()
		if err != nil {
			conn.CloseWithError(0, "Handshake read error")
			return fmt.Errorf("handshake read error #%d: %v", i+1, err)
		}
		stream.SetReadDeadline(time.Time{})

		var resp HandshakeResp
		if err := json.Unmarshal(respData, &resp); err != nil || !resp.Success {
			putFrame(respData)
			conn.CloseWithError(0, "Handshake rejected")
			return fmt.Errorf("handshake failed #%d: %v", i+1, err)
		}
		putFrame(respData)

		if i == 0 {
			firstResp = resp
		}
		pool.Add(conn, stream)
	}

	log.Infof("Tunnel negotiated across %d connections! IPv4: %s (GW: %s) | IPv6: %s (GW: %s)", pool.Size(), firstResp.IPv4, firstResp.GwV4, firstResp.IPv6, firstResp.GwV6)

	if err := c.setupInterface(firstResp.IPv4, firstResp.IPv6); err != nil {
		return fmt.Errorf("TAP interface setup failed: %v", err)
	}

	if err := setupPolicyRouting(c.tapName, c.fwmark, firstResp.GwV4, firstResp.GwV6); err != nil {
		log.Warnf("Policy routing setup failed: %v", err)
	}
	defer cleanPolicyRouting(c.tapName, c.fwmark, firstResp.GwV4, firstResp.GwV6)

	errChan := make(chan error, 4)
	fecDec := NewFECDecoder()
	fecEnc, _ := NewFECEncoder(c.fecData, c.fecParity)

	// Datagram 与 Stream 接收
	pool.mu.RLock()
	for idx, conn := range pool.conns {
		st := pool.streams[idx]
		cRef := conn
		stRef := st

		if c.useDatagram {
			go func(cn *quic.Conn) {
				for {
					data, err := cn.ReceiveDatagram(runCtx)
					if err != nil {
						return
					}
					if len(data) > 0 {
						frames := fecDec.Input(data)
						for _, frame := range frames {
							if _, err := c.tap.Write(frame); err != nil {
								log.Errorf("[Rx-Datagram] TAP Write Error: %v", err)
							}
							putFrame(frame)
						}
					}
				}
			}(cRef)
		}

		go func(st *quic.Stream) {
			sc := NewFrameScanner(st)
			for {
				select {
				case <-runCtx.Done():
					return
				default:
					pkt, err := sc.ReadFrame()
					if err != nil {
						errChan <- err
						return
					}
					frames := fecDec.Input(pkt)
					putFrame(pkt)
					for _, frame := range frames {
						if _, err := c.tap.Write(frame); err != nil {
							log.Errorf("[Rx-Stream] TAP Write Error: %v", err)
						}
						putFrame(frame)
					}
				}
			}
		}(stRef)
	}
	pool.mu.RUnlock()

	// 发送协程
	go func() {
		for {
			jitterDelay := time.Duration(mathrand.Intn(3000)+4000) * time.Millisecond

			select {
			case <-runCtx.Done():
				return
			case frame := <-c.tapTxChan:
				c.shaper.Delay() // 抗 AI 时序塑造

				if fecEnc != nil {
					shards := fecEnc.Input(frame)
					putFrame(frame)
					for _, shard := range shards {
						err := pool.SendDatagramOrStream(shard, c.useDatagram)
						putFrame(shard)
						if err != nil {
							errChan <- err
							return
						}
					}
				} else {
					err := pool.SendDatagramOrStream(frame, c.useDatagram)
					putFrame(frame)
					if err != nil {
						errChan <- err
						return
					}
				}
			case <-time.After(jitterDelay):
				if err := pool.SendDatagramOrStream(nil, c.useDatagram); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	log.Infof("QUIC Tunnel Data Plane Active (%d Conns Bonding, SO_BUF: %dMB).", pool.Size(), c.soBufSize/(1024*1024))

	select {
	case err := <-errChan:
		return err
	case <-runCtx.Done():
		return nil
	}
}

func (c *Client) setupInterface(v4cidr, v6cidr string) error {
	v4Net, v6Net := parseCIDRHelper(v4cidr, v6cidr)
	v4IP := strings.Split(v4cidr, "/")[0]
	v6IP := strings.Split(v6cidr, "/")[0]
	return configureTAPInterface(c.tapName, v4IP, v6IP, v4Net, v6Net)
}

func parseCIDRHelper(v4cidr, v6cidr string) (*net.IPNet, *net.IPNet) {
	var v4n, v6n *net.IPNet
	if v4cidr != "" && v4cidr != "/" {
		_, v4n, _ = net.ParseCIDR(v4cidr)
	}
	if v6cidr != "" && v6cidr != "/" {
		_, v6n, _ = net.ParseCIDR(v6cidr)
	}
	return v4n, v6n
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
