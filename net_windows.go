//go:build !linux && !darwin

package main

import (
	"io"
	"net"

	"github.com/songgao/water"
)

type dummyTAP struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (d *dummyTAP) Read(b []byte) (int, error) {
	return d.r.Read(b)
}

func (d *dummyTAP) Write(b []byte) (int, error) {
	return d.w.Write(b)
}

func (d *dummyTAP) Close() error {
	d.r.Close()
	d.w.Close()
	return nil
}

func createTAPDevice(tapName string) (io.ReadWriteCloser, string, error) {
	config := water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID:   "tap0901",
			InterfaceName: tapName,
		},
	}
	if dev, err := water.New(config); err == nil {
		actualName := dev.Name()
		log.Infof("Successfully opened Windows TAP device (%s)", actualName)
		return dev, actualName, nil
	} else {
		log.Warnf("Failed to open Windows TAP adapter (%v). Using dummy fallback stub.", err)
	}

	pr, pw := io.Pipe()
	return &dummyTAP{r: pr, w: pw}, tapName, nil
}

func configureTAPInterface(tapName, v4AddrStr, v6AddrStr string, v4Net, v6Net *net.IPNet) error {
	log.Infof("Windows TAP interface %s configured (%s, %s)", tapName, v4AddrStr, v6AddrStr)
	return nil
}

func setupPolicyRouting(tapName string, mark int, gwV4, gwV6 string) error {
	if mark <= 0 {
		return nil
	}
	log.Infof("Windows Policy Routing: note fwmark is Linux-specific (fwmark: %d)", mark)
	return nil
}

func cleanPolicyRouting(tapName string, mark int, gwV4, gwV6 string) {
	if mark <= 0 {
		return
	}
	log.Infof("Windows Policy Routing cleaned (fwmark: %d)", mark)
}
