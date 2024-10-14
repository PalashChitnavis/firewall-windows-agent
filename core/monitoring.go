package core

import (
	"firewall-windows-agent/utils"
	"fmt"
	"log"
	"sync"

	"github.com/google/gopacket/pcap"
)

// Monitor captures packets from all available network interfaces
func Monitor() {
    // Find all devices (network interfaces)
    devices, err := utils.StartMonitoring()
    if err != nil {
        log.Fatal(err)
    }

    // Use a WaitGroup to ensure all packet capturing is handled correctly
    var wg sync.WaitGroup

    // Capture packets from all devices concurrently for both incoming and outgoing traffic
    for _, device := range devices {
        fmt.Printf("Starting capture on device: %s\n", device.Name)

        // Start goroutine for incoming packets
        wg.Add(1)
        go utils.CapturePackets(device, pcap.DirectionIn, &wg)

        // Start goroutine for outgoing packets
        wg.Add(1)
        go utils.CapturePackets(device, pcap.DirectionOut, &wg)
    }

    // Wait for all goroutines to finish before exiting the function
    wg.Wait()
}


