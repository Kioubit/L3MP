package loader

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type egress_settings multiplex multiplex.c

type Loader struct {
	objs              *multiplexObjects
	externalInterface netlink.Link
	externalQDisc     *netlink.GenericQdisc
}

func NewLoader() (*Loader, error) {
	loader := &Loader{}
	loader.objs = &multiplexObjects{}
	err := loadMultiplexObjects(loader.objs, nil)
	if err != nil {
		return nil, err
	}
	return loader, nil
}

func (l *Loader) Close() {
	_ = l.objs.Close()
	if l.externalQDisc != nil {
		err := netlink.QdiscDel(l.externalQDisc)
		if err != nil {
			fmt.Println("qDisc deletion error:", err)
		}
	}
}

func (l *Loader) ApplyExternal(dev netlink.Link) error {
	// ===== Ingress from the external interface ======
	qDisc, err := attachFilter(dev.Attrs().Index, l.objs.multiplexPrograms.Ingress, false)
	if err != nil {
		return fmt.Errorf("attach filter: %w", err)
	}
	l.externalQDisc = qDisc
	l.externalInterface = dev
	return nil
}

func (l *Loader) ApplyToManaged(dev netlink.Link, label uint32) (err error) {
	if label > 16 {
		return fmt.Errorf("invalid label: %d", label)
	}
	if l.externalInterface == nil {
		return fmt.Errorf("no external interface")
	}
	err = l.objs.IngressDestinationsMap.Put(label, uint32(dev.Attrs().Index))
	if err != nil {
		return fmt.Errorf("ingress destinations map: %w", err)
	}

	// ===== Egress from the managed interface ======
	_, err = attachFilter(dev.Attrs().Index, l.objs.multiplexPrograms.Egress, true)
	if err != nil {
		return fmt.Errorf("attach filter: %w", err)
	}

	settings := multiplexEgressSettings{
		ExternalInterface: uint32(l.externalInterface.Attrs().Index),
		EgressID:          label,
	}
	err = l.objs.SettingsMap.Put(uint32(0), settings)
	if err != nil {
		return fmt.Errorf("settings map: %w", err)
	}
	return nil
}

func attachFilter(devIndex int, program *ebpf.Program, egress bool) (*netlink.GenericQdisc, error) {
	qDisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devIndex,
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
			LinkIndex: devIndex,
			Parent:    uint32(parent),
			Handle:    1,
			Priority:  1,
			Protocol:  unix.ETH_P_ALL,
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

// IncreaseResourceLimits https://prototype-kernel.readthedocs.io/en/latest/bpf/troubleshooting.html#memory-ulimits
func IncreaseResourceLimits() error {
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})
}
