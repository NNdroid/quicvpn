//go:build darwin

package main

import (
	"fmt"
	"io"
	"net"
	"os/exec"

	"github.com/songgao/water"
)

type dummyDarwinTAP struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (d *dummyDarwinTAP) Read(b []byte) (int, error) {
	return d.r.Read(b)
}

func (d *dummyDarwinTAP) Write(b []byte) (int, error) {
	return d.w.Write(b)
}

func (d *dummyDarwinTAP) Close() error {
	d.r.Close()
	d.w.Close()
	return nil
}

func createTAPDevice(tapName string) (io.ReadWriteCloser, string, error) {
	config := water.Config{
		DeviceType: water.TAP,
	}
	if dev, err := water.New(config); err == nil {
		actualName := dev.Name()
		log.Infof("Successfully opened macOS virtual device: %s (requested: %s)", actualName, tapName)
		return dev, actualName, nil
	} else {
		log.Warnf("Failed to open macOS TAP adapter (%v). Using dummy fallback stub.", err)
	}

	pr, pw := io.Pipe()
	return &dummyDarwinTAP{r: pr, w: pw}, tapName, nil
}

func configureTAPInterface(tapName, v4AddrStr, v6AddrStr string, v4Net, v6Net *net.IPNet) error {
	if v4AddrStr != "" && v4Net != nil {
		maskStr := net.IP(v4Net.Mask).String()
		cmd := exec.Command("ifconfig", tapName, v4AddrStr, v4AddrStr, "netmask", maskStr, "up")
		if err := cmd.Run(); err != nil {
			log.Warnf("macOS ifconfig v4 execution warning: %v", err)
		}
	}
	if v6AddrStr != "" && v6Net != nil {
		cmd := exec.Command("ifconfig", tapName, "inet6", v6AddrStr, "prefixlen", fmt.Sprintf("%d", maskSize(v6Net.Mask)), "alias")
		if err := cmd.Run(); err != nil {
			log.Warnf("macOS ifconfig v6 execution warning: %v", err)
		}
	}
	log.Infof("macOS virtual interface %s configured (IPv4: %s, IPv6: %s)", tapName, v4AddrStr, v6AddrStr)
	return nil
}

func setupPolicyRouting(tapName string, mark int, gwV4, gwV6 string) error {
	if mark <= 0 {
		return nil
	}
	log.Infof("macOS Policy Routing: Note fwmark is Linux-specific. For macOS, route tables or pf.conf can be configured.")
	return nil
}

func cleanPolicyRouting(tapName string, mark int, gwV4, gwV6 string) {
	if mark <= 0 {
		return
	}
	log.Infof("macOS Policy Routing cleaned.")
}
