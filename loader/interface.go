package loader

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
)

func getInterface(name string) *net.Interface {
	dev, err := net.InterfaceByName(name)
	if err != nil {
		log.Fatal(err)
	}
	return dev
}

func createInterface(interfaceName string) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = interfaceName

	_, err := water.New(config)
	if err != nil {
		log.Fatal("Is the 'tun' device available? Failed creating TUN interface ", interfaceName, " - ", err)
	}
}

func attachFilter(dev *net.Interface, program *ebpf.Program, egress bool) (*netlink.GenericQdisc, error) {
	qDisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: dev.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	err := netlink.QdiscReplace(qDisc)
	if err != nil {
		return nil, fmt.Errorf("qDisc replace error: %w", err)
	}

	parent := netlink.HANDLE_MIN_EGRESS
	if !egress {
		parent = netlink.HANDLE_MIN_INGRESS
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: dev.Index,
			Parent:    uint32(parent),
			Handle:    1,
			Protocol:  unix.ETH_P_ALL, // TODO TRY ETH_P_IP AND ETH_P_IP6
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("tc filter replace error: %w", err)
	}
	return qDisc, nil
}
