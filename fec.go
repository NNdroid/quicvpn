package main

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/klauspost/reedsolomon"
)

// FECHeader: 9 字节前向纠错头部
// 格式: [GroupSeq (4B)][ShardIdx (1B)][TotalShards (1B)][DataShards (1B)][PayloadLen (2B)]
const fecHeaderLen = 9

type FECFrame struct {
	GroupSeq    uint32
	ShardIdx    uint8
	TotalShards uint8
	DataShards  uint8
	PayloadLen  uint16
	Data        []byte
}

func encodeFECHeader(buf []byte, groupSeq uint32, shardIdx, totalShards, dataShards uint8, payloadLen uint16) {
	binary.BigEndian.PutUint32(buf[0:4], groupSeq)
	buf[4] = shardIdx
	buf[5] = totalShards
	buf[6] = dataShards
	binary.BigEndian.PutUint16(buf[7:9], payloadLen)
}

func decodeFECHeader(buf []byte) (FECFrame, error) {
	if len(buf) < fecHeaderLen {
		return FECFrame{}, fmt.Errorf("buffer too short for FEC header: %d", len(buf))
	}
	return FECFrame{
		GroupSeq:    binary.BigEndian.Uint32(buf[0:4]),
		ShardIdx:    buf[4],
		TotalShards: buf[5],
		DataShards:  buf[6],
		PayloadLen:  binary.BigEndian.Uint16(buf[7:9]),
		Data:        buf[fecHeaderLen:],
	}, nil
}

// ======================= FEC 编码器 =======================
type FECEncoder struct {
	dataShards   int
	parityShards int
	enc          reedsolomon.Encoder
	mu           sync.Mutex
	groupSeq     uint32
	pending      [][]byte
	lens         []uint16
}

func NewFECEncoder(dataShards, parityShards int) (*FECEncoder, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return nil, nil
	}
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, err
	}
	return &FECEncoder{
		dataShards:   dataShards,
		parityShards: parityShards,
		enc:          enc,
		pending:      make([][]byte, 0, dataShards),
		lens:         make([]uint16, 0, dataShards),
	}, nil
}

// Input 输入一个原始帧，若凑满组则返回编码后的全部切片（含数据与冗余包）
func (e *FECEncoder) Input(frame []byte) [][]byte {
	if e == nil || e.dataShards <= 0 {
		buf := getFrame()[:len(frame)]
		copy(buf, frame)
		return [][]byte{buf}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	buf := getFrame()[:len(frame)]
	copy(buf, frame)
	e.pending = append(e.pending, buf)
	e.lens = append(e.lens, uint16(len(frame)))

	if len(e.pending) < e.dataShards {
		return nil
	}

	// 找出本组最大长度
	maxLen := 0
	for _, l := range e.lens {
		if int(l) > maxLen {
			maxLen = int(l)
		}
	}
	if maxLen == 0 {
		maxLen = 64
	}

	totalShards := e.dataShards + e.parityShards
	shards := make([][]byte, totalShards)

	for i := 0; i < e.dataShards; i++ {
		shards[i] = getFrame()[:maxLen]
		copy(shards[i], e.pending[i])
		if len(e.pending[i]) < maxLen {
			clear(shards[i][len(e.pending[i]):maxLen])
		}
	}

	for i := e.dataShards; i < totalShards; i++ {
		shards[i] = getFrame()[:maxLen]
	}

	_ = e.enc.Encode(shards)

	e.groupSeq++
	groupSeq := e.groupSeq

	result := make([][]byte, totalShards)
	for i := 0; i < totalShards; i++ {
		pkt := getFrame()[:fecHeaderLen+maxLen]
		var origLen uint16
		if i < e.dataShards {
			origLen = e.lens[i]
		} else {
			origLen = uint16(maxLen)
		}
		encodeFECHeader(pkt, groupSeq, uint8(i), uint8(totalShards), uint8(e.dataShards), origLen)
		copy(pkt[fecHeaderLen:], shards[i])
		result[i] = pkt

		putFrame(shards[i])
	}

	// 清理 pending
	for _, p := range e.pending {
		putFrame(p)
	}
	e.pending = e.pending[:0]
	e.lens = e.lens[:0]

	return result
}

// ======================= FEC 解码器 =======================
type fecGroup struct {
	received      map[uint8][]byte
	lens          map[uint8]uint16
	totalShards   uint8
	dataShards    uint8
	createdAt     time.Time
	reconstructed bool
}

type FECDecoder struct {
	mu     sync.Mutex
	groups map[uint32]*fecGroup
}

func NewFECDecoder() *FECDecoder {
	d := &FECDecoder{
		groups: make(map[uint32]*fecGroup),
	}
	go d.gcLoop()
	return d
}

func (d *FECDecoder) Input(pkt []byte) [][]byte {
	if len(pkt) < fecHeaderLen {
		buf := getFrame()[:len(pkt)]
		copy(buf, pkt)
		return [][]byte{buf}
	}

	hdr, err := decodeFECHeader(pkt)
	if err != nil || hdr.TotalShards == 0 || hdr.DataShards == 0 {
		buf := getFrame()[:len(pkt)]
		copy(buf, pkt)
		return [][]byte{buf}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	group, exists := d.groups[hdr.GroupSeq]
	if !exists {
		group = &fecGroup{
			received:    make(map[uint8][]byte),
			lens:        make(map[uint8]uint16),
			totalShards: hdr.TotalShards,
			dataShards:  hdr.DataShards,
			createdAt:   time.Now(),
		}
		d.groups[hdr.GroupSeq] = group
	}

	if group.reconstructed {
		return nil
	}

	if _, has := group.received[hdr.ShardIdx]; !has {
		shardCopy := getFrame()[:len(hdr.Data)]
		copy(shardCopy, hdr.Data)
		group.received[hdr.ShardIdx] = shardCopy
		group.lens[hdr.ShardIdx] = hdr.PayloadLen
	}

	// 检查是否凑齐了足够的分片进行解码
	if len(group.received) >= int(hdr.DataShards) {
		group.reconstructed = true
		delete(d.groups, hdr.GroupSeq)

		// 检查是否所有原始数据分片都在
		allDataPresent := true
		for i := uint8(0); i < hdr.DataShards; i++ {
			if _, ok := group.received[i]; !ok {
				allDataPresent = false
				break
			}
		}

		recoveredFrames := make([][]byte, 0, hdr.DataShards)

		if allDataPresent {
			for i := uint8(0); i < hdr.DataShards; i++ {
				data := group.received[i]
				origLen := int(group.lens[i])
				if origLen > len(data) {
					origLen = len(data)
				}
				frame := getFrame()[:origLen]
				copy(frame, data[:origLen])
				recoveredFrames = append(recoveredFrames, frame)
				putFrame(data)
			}
			// 清理冗余包
			for i := hdr.DataShards; i < hdr.TotalShards; i++ {
				if data, ok := group.received[i]; ok {
					putFrame(data)
				}
			}
			return recoveredFrames
		}

		// 使用 Reed-Solomon 重建缺失分片
		enc, err := reedsolomon.New(int(hdr.DataShards), int(hdr.TotalShards-hdr.DataShards))
		if err != nil {
			return nil
		}

		maxLen := 0
		for _, data := range group.received {
			if len(data) > maxLen {
				maxLen = len(data)
			}
		}

		shards := make([][]byte, hdr.TotalShards)
		for i := uint8(0); i < hdr.TotalShards; i++ {
			if data, ok := group.received[i]; ok {
				shards[i] = getFrame()[:maxLen]
				copy(shards[i], data)
				putFrame(data)
			} else {
				shards[i] = nil
			}
		}

		if err := enc.Reconstruct(shards); err == nil {
			for i := uint8(0); i < hdr.DataShards; i++ {
				if shards[i] != nil {
					origLen := int(group.lens[i])
					if origLen == 0 || origLen > len(shards[i]) {
						origLen = len(shards[i])
					}
					frame := getFrame()[:origLen]
					copy(frame, shards[i][:origLen])
					recoveredFrames = append(recoveredFrames, frame)
					putFrame(shards[i])
				}
			}
			for i := hdr.DataShards; i < hdr.TotalShards; i++ {
				if shards[i] != nil {
					putFrame(shards[i])
				}
			}
			return recoveredFrames
		}
	}

	return nil
}

func (d *FECDecoder) gcLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		d.mu.Lock()
		now := time.Now()
		for seq, group := range d.groups {
			if now.Sub(group.createdAt) > 5*time.Second {
				for _, b := range group.received {
					putFrame(b)
				}
				delete(d.groups, seq)
			}
		}
		d.mu.Unlock()
	}
}
