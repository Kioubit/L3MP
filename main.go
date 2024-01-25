package main

import (
	"L3MP/loader"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) != 3 {
		showUsage()
	}

	externalInterface := os.Args[1]
	managedInterfaces := make(map[string]int)
	readConfig(os.Args[2], managedInterfaces)

	l := loader.LoadEBPF(externalInterface, managedInterfaces)
	defer l.Close()
	waitForSignal()
}

func showUsage() {
	fmt.Println("Usage", os.Args[0], "<external interface> <path to file with interface-label definitions>")
	fmt.Println("The interface-label definitions file contains up to 16 entries in this format:")
	fmt.Println("<interface name>@<label>")
	fmt.Println("Where <label> is a number from 0 to 16")
	os.Exit(2)
}

func waitForSignal() {
	var sigCh = make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	close(sigCh)
}
