package main

import (
	"github.com/vishvananda/netlink"
)

func createInterface(interfaceName string, mtu int) (tun netlink.Link, err error) {
	tun = &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: interfaceName,
		},
		Mode: netlink.TUNTAP_MODE_TUN,
	}
	err = netlink.LinkAdd(tun)
	if err != nil {
		return
	}

	err = netlink.LinkSetMTU(tun, mtu)
	if err != nil {
		return
	}
	return
}

func deleteInterface(link netlink.Link) (err error) {
	return netlink.LinkDel(link)
}

func resolveInterface(interfaceName string) (link netlink.Link, err error) {
	return netlink.LinkByName(interfaceName)
}
