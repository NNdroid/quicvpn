package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func init() {
	initLogger("error")
}

// ==========================================
// 1. 全面单元测试 (Comprehensive Unit Tests)
// ==========================================

// TestSummarizeFrame 测试以太网/IPv4/IPv6帧解析器
func TestSummarizeFrame(t *testing.T) {
	tests := []struct {
		name     string
		frame    []byte
		expected string
	}{
		{
			name:     "Invalid short frame",
			frame:    []byte{0x01, 0x02, 0x03},
			expected: "Invalid Frame (len: 3)",
		},
		{
			name: "Dummy IPv4 ICMP Ping Frame",
			frame: []byte{
				0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // Dst MAC
				0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // Src MAC
				0x08, 0x00, // EtherType: IPv4
				0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // Proto=1 (ICMP)
				0, 0, // Checksum
				1, 1, 1, 1, // Src IP
				2, 2, 2, 2, // Dst IP
			},
			expected: "IPv4 | 11:11:11:11:11:11 -> 22:22:22:22:22:22 | [ICMP] 1.1.1.1 -> 2.2.2.2",
		},
		{
			name: "Dummy IPv4 TCP Frame",
			frame: []byte{
				0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
				0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
				0x08, 0x00,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 6, // Proto=6 (TCP)
				0, 0,
				10, 0, 0, 1, // Src IP
				10, 0, 0, 2, // Dst IP
			},
			expected: "IPv4 | 11:11:11:11:11:11 -> 22:22:22:22:22:22 | [TCP] 10.0.0.1 -> 10.0.0.2",
		},
		{
			name: "Dummy IPv6 UDP Frame",
			frame: func() []byte {
				f := make([]byte, 54)
				copy(f[0:6], []byte{0x44, 0x44, 0x44, 0x44, 0x44, 0x44}) // Dst
				copy(f[6:12], []byte{0x33, 0x33, 0x33, 0x33, 0x33, 0x33}) // Src
				binary.BigEndian.PutUint16(f[12:14], 0x86DD)            // IPv6
				f[20] = 17                                               // NextHeader=UDP
				copy(f[22:38], net.ParseIP("fd00::1"))
				copy(f[38:54], net.ParseIP("fd00::2"))
				return f
			}(),
			expected: "IPv6 | 33:33:33:33:33:33 -> 44:44:44:44:44:44 | [NextHeader-UDP] fd00::1 -> fd00::2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := summarizeFrame(tt.frame)
			if res != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, res)
			}
		})
	}
}

// TestFrameScanner 测试核心粘包/拆包及异常损坏恢复机制
func TestFrameScanner(t *testing.T) {
	payload1 := []byte("Hello")
	payload2 := []byte("QUIC")
	payload3 := []byte("VPN")

	var buf bytes.Buffer

	writePkt := func(p []byte) {
		head := make([]byte, 2)
		binary.BigEndian.PutUint16(head, uint16(len(p)))
		buf.Write(head)
		buf.Write(p)
	}

	writePkt(payload1)
	writePkt(payload2)
	writePkt(payload3)

	scanner := NewFrameScanner(&buf)

	expected := [][]byte{payload1, payload2, payload3}
	for i, exp := range expected {
		frame, err := scanner.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame %d failed: %v", i, err)
		}
		if !bytes.Equal(frame, exp) {
			t.Errorf("Frame %d mismatch. Expected %s, got %s", i, exp, frame)
		}
		putFrame(frame)
	}
}

// TestBuildPaddedFrame 测试所有 Padding 模式
func TestBuildPaddedFrame(t *testing.T) {
	raw := []byte("12345678901234567890") // 20 bytes
	rn := len(raw)

	// Block 模式
	blockFrame := buildPaddedFrame(raw, rn, "block", 128, 1420)
	if len(blockFrame) != 128 {
		t.Errorf("Block mode length expected 128, got %d", len(blockFrame))
	}
	if !bytes.Equal(blockFrame[:rn], raw) {
		t.Errorf("Block mode payload corrupted")
	}
	putFrame(blockFrame)

	// MTU 模式
	mtuFrame := buildPaddedFrame(raw, rn, "mtu", 128, 1420)
	if len(mtuFrame) != 1420 {
		t.Errorf("MTU mode length expected 1420, got %d", len(mtuFrame))
	}
	putFrame(mtuFrame)

	// Off 模式
	offFrame := buildPaddedFrame(raw, rn, "off", 128, 1420)
	if len(offFrame) != rn {
		t.Errorf("Off mode length expected %d, got %d", rn, len(offFrame))
	}
	putFrame(offFrame)
}

// TestFEC_EncodeDecode 验证 Reed-Solomon 丢包纠错能力
func TestFEC_EncodeDecode(t *testing.T) {
	dataShards := 10
	parityShards := 2
	enc, err := NewFECEncoder(dataShards, parityShards)
	if err != nil {
		t.Fatalf("Failed to create FEC encoder: %v", err)
	}
	dec := NewFECDecoder()

	var allShards [][]byte
	originalPackets := make([][]byte, dataShards)

	for i := 0; i < dataShards; i++ {
		pkt := []byte(fmt.Sprintf("Packet-Payload-%d-Data", i))
		originalPackets[i] = pkt
		res := enc.Input(pkt)
		if i == dataShards-1 {
			allShards = res
		}
	}

	if len(allShards) != dataShards+parityShards {
		t.Fatalf("Expected %d total shards, got %d", dataShards+parityShards, len(allShards))
	}

	// 模拟丢包：丢弃 2 个分片 (index 2 和 7)
	receivedShards := make([][]byte, 0)
	for idx, shard := range allShards {
		if idx == 2 || idx == 7 {
			putFrame(shard)
			continue
		}
		receivedShards = append(receivedShards, shard)
	}

	var reconstructed [][]byte
	for _, shard := range receivedShards {
		frames := dec.Input(shard)
		putFrame(shard)
		if len(frames) > 0 {
			reconstructed = frames
		}
	}

	if len(reconstructed) != dataShards {
		t.Fatalf("FEC Reconstruction failed! Expected %d reconstructed frames, got %d", dataShards, len(reconstructed))
	}

	for i := 0; i < dataShards; i++ {
		if !bytes.Equal(reconstructed[i], originalPackets[i]) {
			t.Errorf("Reconstructed packet %d mismatch. Expected %s, got %s", i, originalPackets[i], reconstructed[i])
		}
		putFrame(reconstructed[i])
	}
}

// TestTimingShaper 测试抗 AI 泊松微抖动塑造器
func TestTimingShaper(t *testing.T) {
	disabledShaper := NewTimingShaper(false, 50)
	start := time.Now()
	disabledShaper.Delay()
	if time.Since(start) > 1*time.Millisecond {
		t.Errorf("Disabled shaper should not sleep")
	}

	enabledShaper := NewTimingShaper(true, 50)
	start = time.Now()
	enabledShaper.Delay()
	elapsed := time.Since(start)
	if elapsed < 5*time.Microsecond || elapsed > 10*time.Millisecond {
		t.Errorf("Enabled shaper delay out of range: %v", elapsed)
	}
}

// TestAsyncPort_Batching 测试 AsyncPort 批量 Ring-Batching 机制
func TestAsyncPort_Batching(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var receivedCount int32
	var mu sync.Mutex
	receivedFrames := make([][]byte, 0)

	port := NewAsyncPort(ctx, "TestPort", func(b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		if len(b) > 0 {
			receivedFrames = append(receivedFrames, bytes.Clone(b))
			receivedCount++
		}
		return nil
	})
	defer port.Close()

	// 快速压入 100 个数据帧
	totalToSend := 100
	for i := 0; i < totalToSend; i++ {
		pkt := []byte(fmt.Sprintf("Frame-%d", i))
		_ = port.WriteFrame(pkt)
	}

	// 等待批处理刷新完成
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	count := len(receivedFrames)
	mu.Unlock()

	if count != totalToSend {
		t.Errorf("Expected AsyncPort batching to receive %d frames, got %d", totalToSend, count)
	}
}

// mockPort 用于模拟 VSwitch 的物理网卡或隧道端口
type mockPort struct {
	id     string
	frames [][]byte
	mu     sync.Mutex
}

func (m *mockPort) ID() string { return m.id }
func (m *mockPort) WriteFrame(frame []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frames = append(m.frames, frame)
	return nil
}

// TestVSwitch_LearningAndForwarding 测试交换机 MAC 学习、单播与泛洪
func TestVSwitch_LearningAndForwarding(t *testing.T) {
	vswitch := NewVSwitch()
	portA := &mockPort{id: "PortA"}
	portB := &mockPort{id: "PortB"}
	vswitch.AddPort(portA)
	vswitch.AddPort(portB)

	bumFrame := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0x08, 0x00,
	}

	vswitch.ProcessFrame("PortA", bumFrame)

	portB.mu.Lock()
	if len(portB.frames) != 1 {
		t.Errorf("PortB should receive 1 flooded frame, got %d", len(portB.frames))
	}
	portB.mu.Unlock()

	unicastFrame := []byte{
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
		0x08, 0x00,
	}

	vswitch.ProcessFrame("PortB", unicastFrame)

	portA.mu.Lock()
	if len(portA.frames) != 1 {
		t.Errorf("PortA should receive 1 unicast frame, got %d", len(portA.frames))
	}
	portA.mu.Unlock()
}

// ==========================================
// 2. 深入基准测试 (Comprehensive Benchmarks)
// ==========================================

func BenchmarkSummarizeFrame(b *testing.B) {
	frame := []byte{
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		0x08, 0x00,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0, 0,
		192, 168, 1, 1,
		192, 168, 1, 2,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summarizeFrame(frame)
	}
}

func BenchmarkBuildPaddedFrame(b *testing.B) {
	raw := make([]byte, 256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := buildPaddedFrame(raw, 256, "block", 128, 1420)
		putFrame(f)
	}
}

func BenchmarkFEC_Encoder(b *testing.B) {
	enc, _ := NewFECEncoder(10, 2)
	raw := make([]byte, 500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res := enc.Input(raw)
		for _, s := range res {
			putFrame(s)
		}
	}
}

func BenchmarkTimingShaper(b *testing.B) {
	shaper := NewTimingShaper(true, 50)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shaper.Delay()
	}
}

func BenchmarkVSwitch_ProcessFrame(b *testing.B) {
	vswitch := NewVSwitch()
	portA := &mockPort{id: "PortA"}
	portB := &mockPort{id: "PortB"}
	vswitch.AddPort(portA)
	vswitch.AddPort(portB)

	frame := []byte{
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
		0x08, 0x00,
	}

	macAA := [6]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
	vswitch.macTable[macAA] = macEntry{portID: "PortA", updatedAt: time.Now()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vswitch.ProcessFrame("PortB", frame)
	}
}

func BenchmarkVSwitch_Parallel(b *testing.B) {
	vswitch := NewVSwitch()
	portA := &mockPort{id: "PortA"}
	vswitch.AddPort(portA)

	macAA := [6]byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}
	vswitch.macTable[macAA] = macEntry{portID: "PortA", updatedAt: time.Now()}

	frame := []byte{
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
		0x08, 0x00,
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			vswitch.ProcessFrame("PortB", frame)
		}
	})
}
