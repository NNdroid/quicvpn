//go:build linux

package main

import (
	"fmt"
	"io"
	"net"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

func createTAPDevice(tapName string) (io.ReadWriteCloser, string, error) {
	config := water.Config{DeviceType: water.TAP}
	config.Name = tapName
	dev, err := water.New(config)
	if err != nil {
		return nil, tapName, err
	}
	return dev, dev.Name(), nil
}

func configureTAPInterface(tapName, v4AddrStr, v6AddrStr string, v4Net, v6Net *net.IPNet) error {
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("failed to find link %s: %v", tapName, err)
	}

	if v4AddrStr != "" && v4Net != nil {
		if v4Addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", v4AddrStr, maskSize(v4Net.Mask))); err == nil {
			netlink.AddrReplace(link, v4Addr)
		}
	}
	if v6AddrStr != "" && v6Net != nil {
		if v6Addr, err := netlink.ParseAddr(fmt.Sprintf("%s/%d", v6AddrStr, maskSize(v6Net.Mask))); err == nil {
			netlink.AddrReplace(link, v6Addr)
		}
	}

	return netlink.LinkSetUp(link)
}

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
