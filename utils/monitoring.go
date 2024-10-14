package utils

import (
	"errors"
	"fmt"
	"log"
	"sync"

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

// capturePackets captures packets on a specific network device based on the direction (incoming or outgoing).
func CapturePackets(device pcap.Interface, direction pcap.Direction, wg *sync.WaitGroup) {
	defer wg.Done() // Ensure the WaitGroup is done after execution

	// Open the device for packet capture
	handle, err := pcap.OpenLive(device.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error opening device %s: %v\n", device.Name, err)
		return
	}
	defer handle.Close()

	// Set the direction (incoming or outgoing)
	handle.SetDirection(direction); 

	// Use gopacket to process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetStruct := ProcessPacket(packet, device , direction)
        packetStruct.Print()
    }
}