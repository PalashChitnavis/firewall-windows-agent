package utils

import (
	"errors"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// StartMonitoring retrieves all available network devices and returns them as a slice.
func StartMonitoring() ([]pcap.Interface, error) {
    // Get the list of network devices
    devices, err := pcap.FindAllDevs()
    if err != nil {
        log.Println("Error finding network devices:", err)
        return nil, err
    }

    // Check if no devices were found
    if len(devices) == 0 {
        return nil, errors.New("no network devices found")
    }

    // Log the found devices (optional)
    fmt.Println("Available network devices:")
    for _, device := range devices {
        fmt.Printf("Name: %s, Description: %s, Flags: %v\n", device.Name, device.Description, device.Flags)
    }

    return devices, nil
}

// capturePackets captures packets on a specific network device
func CapturePackets(device pcap.Interface) {
    // Open the device for packet capture
    handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
    if err != nil {
        log.Printf("Error opening device %s: %v\n", device.Name, err)
        return
    }
    defer handle.Close()

    // Use gopacket to process packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        direction := directionChecker(packet)
        fmt.Printf("Packet on device %s is: %s\n", device.Description, direction)
    }
}



