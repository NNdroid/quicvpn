package main

import (
	"math"
	mathrand "math/rand"
	"time"
)

// TimingShaper: 基于泊松/指数分布的微抖动时序塑造器，消除 DPI 机器学习特征
type TimingShaper struct {
	enabled  bool
	meanMicro float64
}

func NewTimingShaper(enabled bool, meanMicro int) *TimingShaper {
	if meanMicro <= 0 {
		meanMicro = 50 // 默认平均 50 微秒微抖动
	}
	return &TimingShaper{
		enabled:   enabled,
		meanMicro: float64(meanMicro),
	}
}

func (s *TimingShaper) Delay() {
	if s == nil || !s.enabled {
		return
	}
	// 泊松/指数分布采样: -ln(U) * mean
	u := mathrand.Float64()
	if u <= 0 {
		u = 0.0001
	}
	micro := -math.Log(u) * s.meanMicro

	// 限制微抖动范围在 5us ~ 300us，既打乱时序直方图，又保持 G 级超高吞吐
	if micro < 5 {
		micro = 5
	}
	if micro > 300 {
		micro = 300
	}

	time.Sleep(time.Duration(micro) * time.Microsecond)
}
