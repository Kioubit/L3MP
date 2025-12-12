package main

import (
	"L3MP/loader"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
)

var Version string

var (
	externalIface string
	ifaceLabels   arrayFlags
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ", ")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func init() {
	flag.StringVar(&externalIface, "ext", "", "External interface name (required)")
	flag.Var(&ifaceLabels, "if", "Interface-label pair in format 'interface@label' (can be repeated up to 16 times)")

}

func main() {
	fmt.Println("L3MP", Version)

	flag.Usage = showUsage
	flag.Parse()

	if externalIface == "" {
		fmt.Println("Error: external interface is required")
		showUsage()
	}

	if len(ifaceLabels) == 0 {
		fmt.Println("Error: at least one interface-label pair is required")
		showUsage()
	}

	if len(ifaceLabels) > 16 {
		fmt.Println("Error: maximum 16 interface-label pairs allowed")
		os.Exit(1)
	}

	err := loader.IncreaseResourceLimits()
	if err != nil {
		fmt.Println("Warning: Failed to increase resource limits:", err)
	}

	interfaces := make(map[string]int)
	for _, pair := range ifaceLabels {
		parts := strings.Split(pair, "@")
		if len(parts) != 2 {
			fmt.Printf("Error: invalid format '%s'. Expected 'interface@label'\n", pair)
			os.Exit(1)
		}

		label, err := strconv.Atoi(parts[1])
		if err != nil || label < 0 || label > 16 {
			fmt.Printf("Error: label must be a number from 0 to 16, got '%s'\n", parts[1])
			os.Exit(1)
		}

		interfaces[parts[0]] = label
	}

	fmt.Printf("External interface: %s\n", externalIface)
	fmt.Println("Interface labels:")
	for iface, label := range interfaces {
		fmt.Printf("  %s: %d\n", iface, label)
	}

	l, err := loader.NewLoader()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer l.Close()

	externalDev, err := resolveInterface(externalIface)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = l.ApplyExternal(externalDev)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	managedInterfaces := make(map[netlink.Link]uint32)
	for iface, label := range interfaces {
		dev, err := createInterface(iface, externalDev.Attrs().MTU)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		managedInterfaces[dev] = uint32(label)
		err = l.ApplyToManaged(dev, uint32(label))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	defer func() {
		for dev := range managedInterfaces {
			err = deleteInterface(dev)
			if err != nil {
				fmt.Println("Error removing managed interface", err)
			}
		}
	}()

	waitForSignal()
}

func showUsage() {
	_, _ = fmt.Fprintf(os.Stderr, "Usage: %s -ext <external interface> -if <interface@label> [-if <interface@label> ...]\n\n", os.Args[0])
	_, _ = fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
	_, _ = fmt.Fprintln(os.Stderr, "\nExample:")
	_, _ = fmt.Fprintf(os.Stderr, "  %s -ext eth0 -if mp1@1 -if mp2@2\n", os.Args[0])
	_, _ = fmt.Fprintln(os.Stderr, "\nNotes:")
	_, _ = fmt.Fprintln(os.Stderr, "  - Label must be a number from 0 to 16")
	_, _ = fmt.Fprintln(os.Stderr, "  - Maximum 16 interface-label pairs allowed")
	os.Exit(2)
}

func waitForSignal() {
	var sigCh = make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	close(sigCh)
}
