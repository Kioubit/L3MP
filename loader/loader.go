package loader

import (
	"fmt"
	_ "github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go multiplex ./ebpf/multiplex.c -- -I./ebpf/include/

type Loader struct {
	externalQDisc *netlink.GenericQdisc
}

func getEBGPObjects() *multiplexObjects {
	objs := &multiplexObjects{}
	err := loadMultiplexObjects(objs, nil)
	if err != nil {
		log.Fatal("Load ", err)
	}
	return objs
}

func LoadEBPF(externalInterface string, managedInterfaces map[string]int) *Loader {
	err := increaseResourceLimits()
	if err != nil {
		fmt.Println("Failed to increase resource limits:", err)
	}

	externalDev := getInterface(externalInterface)
	fmt.Println("External interface:", externalDev.Name, "MTU:", externalDev.MTU)
	objs := getEBGPObjects()
	for key, value := range managedInterfaces {
		createInterface(key)

		// Set MTU
		managedDev := getInterface(key)
		link, err := netlink.LinkByIndex(managedDev.Index)
		if err != nil {
			log.Fatalln(err)
		}
		err = netlink.LinkSetMTU(link, externalDev.MTU)
		if err != nil {
			fmt.Println("Failed to set MTU value for the managed link", managedDev.Name)
		}
		// --------
		if value > 16 || value < 0 {
			log.Fatalln("Invalid label")
		}

		err = objs.IngressDestinationsMap.Put(uint32(value), uint32(managedDev.Index))
		if err != nil {
			log.Fatal("Put ", err)
		}
		applyEgress(managedDev, externalDev, value)
		fmt.Println("Tunnel interface:", managedDev.Name, "Label:", value)
	}

	// ===== Ingress from the external interface ======
	qDisc, err := attachFilter(externalDev, objs.multiplexPrograms.Ingress, false)
	if err != nil {
		log.Fatal("Attach ", err)
	}

	_ = objs.Close()

	return &Loader{
		externalQDisc: qDisc,
	}
}
func applyEgress(managedDev *net.Interface, externalDev *net.Interface, label int) {
	// ===== Egress from the managed interface ======
	objs := getEBGPObjects()
	_, err := attachFilter(managedDev, objs.multiplexPrograms.Egress, true)
	if err != nil {
		log.Fatal("Attach ", err)
	}

	// Settings
	settings := struct {
		externalInterface uint32
		egressID          uint32
	}{
		uint32(externalDev.Index),
		uint32(label),
	}
	err = objs.SettingsMap.Put(uint32(0), settings)
	if err != nil {
		log.Fatal("Put ", err)
	}
	_ = objs.Close()
}

// increaseResourceLimits https://prototype-kernel.readthedocs.io/en/latest/bpf/troubleshooting.html#memory-ulimits
func increaseResourceLimits() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}

func (l Loader) Close() {
	err := netlink.QdiscDel(l.externalQDisc)
	if err != nil {
		fmt.Println("qDisc deletion error:", err)
	}
}
