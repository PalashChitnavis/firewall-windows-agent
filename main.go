package main

import (
	"firewall-windows-agent/core"
	"time"
)

func main() {
	go core.Monitor()
	for{
		time.Sleep(1*time.Second)
	}
}