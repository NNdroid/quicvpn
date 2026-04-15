package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// 在测试前初始化日志（设为 Error 级别，防止压测时疯狂刷屏降低性能）
func init() {
	initLogger("error")
}

// ==========================================
// 1. 单元测试 (Unit Tests)
// ==========================================

// TestSummarizeFrame 测试以太网帧解析器
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
			name: "Dummy IPv4 Ping Frame",
			// 伪造一个简单的 34 字节 IPv4 帧 (源MAC:11... 目的MAC:22... 类型:0800, 协议:1(ICMP), 源IP:1.1.1.1 目的:2.2.2.2)
			frame: []byte{
				0x22, 0x22, 0x22, 0x22, 0x22, 0x22, // Dst MAC
				0x11, 0x11, 0x11, 0x11, 0x11, 0x11, // Src MAC
				0x08, 0x00, // EtherType: IPv4
				0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // Offset to Proto, Proto=1 (ICMP)
				0, 0, // Checksum
				1, 1, 1, 1, // Src IP
				2, 2, 2, 2, // Dst IP
			},
			expected: "IPv4 | 11:11:11:11:11:11 -> 22:22:22:22:22:22 | [ICMP] 1.1.1.1 -> 2.2.2.2",
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

// TestFrameScanner 测试核心粘包拆包逻辑
func TestFrameScanner(t *testing.T) {
	// 构造测试数据：3个包“粘”在一起
	payload1 := []byte("Hello")
	payload2 := []byte("QUIC")
	payload3 := []byte("VPN")

	var buf bytes.Buffer
	
	// 辅助函数：打包加上2字节长度头
	writePkt := func(p []byte) {
		head := make([]byte, 2)
		binary.BigEndian.PutUint16(head, uint16(len(p)))
		buf.Write(head)
		buf.Write(p)
	}

	writePkt(payload1)
	writePkt(payload2)
	writePkt(payload3)

	// 使用 bytes.Buffer 模拟网络流 io.Reader
	scanner := NewFrameScanner(&buf)

	// 验证拆包是否正确
	expected := [][]byte{payload1, payload2, payload3}
	for i, exp := range expected {
		frame, err := scanner.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame %d failed: %v", i, err)
		}
		if !bytes.Equal(frame, exp) {
			t.Errorf("Frame %d mismatch. Expected %s, got %s", i, exp, frame)
		}
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

// TestVSwitch_LearningAndForwarding 测试交换机 MAC 学习和转发
func TestVSwitch_LearningAndForwarding(t *testing.T) {
	vswitch := NewVSwitch()
	portA := &mockPort{id: "PortA"}
	portB := &mockPort{id: "PortB"}
	vswitch.AddPort(portA)
	vswitch.AddPort(portB)

	// 伪造一个从 PortA 发出的广播包 (BUM: 目的MAC第一字节奇数, 比如 FF)
	// Src: AA:AA:AA:AA:AA:AA, Dst: FF:FF:FF:FF:FF:FF
	bumFrame := []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dst
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // Src
		0x08, 0x00, // Type
	}

	// 1. PortA 发送广播，VSwitch 应该记录 PortA 的 MAC，并泛洪给 PortB
	vswitch.ProcessFrame("PortA", bumFrame)

	portB.mu.Lock()
	if len(portB.frames) != 1 {
		t.Errorf("PortB should receive 1 flooded frame, got %d", len(portB.frames))
	}
	portB.mu.Unlock()

	// 2. PortB 针对 PortA 发送单播回复
	// Src: BB:BB:BB:BB:BB:BB, Dst: AA:AA:AA:AA:AA:AA
	unicastFrame := []byte{
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // Dst (PortA)
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, // Src (PortB)
		0x08, 0x00, // Type
	}

	// VSwitch 应该学习到 PortB，并且只发给 PortA (不泛洪)
	vswitch.ProcessFrame("PortB", unicastFrame)

	portA.mu.Lock()
	if len(portA.frames) != 1 {
		t.Errorf("PortA should receive 1 unicast frame, got %d", len(portA.frames))
	}
	portA.mu.Unlock()
}

// ==========================================
// 2. 基准测试 (Benchmarks)
// ==========================================

// BenchmarkSummarizeFrame 测试包摘要提取的性能 (内存分配很关键)
func BenchmarkSummarizeFrame(b *testing.T) {
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

// BenchmarkVSwitch_ProcessFrame 测试交换机核心转发引擎的吞吐量
func BenchmarkVSwitch_ProcessFrame(b *testing.T) {
	vswitch := NewVSwitch()
	portA := &mockPort{id: "PortA"}
	portB := &mockPort{id: "PortB"}
	vswitch.AddPort(portA)
	vswitch.AddPort(portB)

	frame := []byte{
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // Dst (已知，所以会走单播)
		0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, // Src
		0x08, 0x00,
	}

	// 先让交换机学习一下 Dst MAC，建立转发表
	vswitch.macTable["aaaaaaaaaaaa"] = &macEntry{portID: "PortA", updatedAt: time.Now()}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vswitch.ProcessFrame("PortB", frame)
	}
}

// BenchmarkVSwitch_Parallel 并发压测交换机（模拟多设备同时发包，测试 RWMutex 的锁竞争）
func BenchmarkVSwitch_Parallel(b *testing.T) {
	vswitch := NewVSwitch()
	portA := &mockPort{id: "PortA"}
	vswitch.AddPort(portA)
	vswitch.macTable["aaaaaaaaaaaa"] = &macEntry{portID: "PortA", updatedAt: time.Now()}

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