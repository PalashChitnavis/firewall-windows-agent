package core

import (
	"firewall-windows-agent/utils"
	"fmt"
	"log"
)

// Monitor captures packets from all available network interfaces
func Monitor() {
    // Find all devices (network interfaces)
    devices, err := utils.StartMonitoring()
    if err != nil {
        log.Fatal(err)
    }

    //Capture packets from all devices concurrently
    for _, device := range devices {
        fmt.Printf("Starting capture on device: %s\n", device.Name)
        go utils.CapturePackets(device)
    }
}


