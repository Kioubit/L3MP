package main

import (
	"log"
	"os"
	"strconv"
	"strings"
)

func readConfig(file string, managedInterfaces map[string]int) {
	f, err := os.ReadFile(file)
	if err != nil {
		log.Fatalln(err)
	}
	lines := strings.Split(string(f), "\n")
	for i, line := range lines {
		kv := strings.Split(strings.TrimSpace(line), "@")
		if len(kv) != 2 {
			log.Fatalln("Invalid config line", i)
		}
		label, err := strconv.Atoi(kv[1])
		if err != nil {
			log.Fatalln("Invalid label at config line", i)
		}
		managedInterfaces[kv[0]] = label
	}

}
