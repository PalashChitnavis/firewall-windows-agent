package types

import (
	"fmt"
)

// Packet struct as defined by you
type Packet struct {
	// Basic Information
	Timestamp           string // Time the packet was captured
	PacketLength        int    // Size of the packet
	Direction           string // Direction (incoming, outgoing, loopback)
	InterfaceName       string // Network interface used
	InterfaceDesc       string // Description of the network interface

	// Link Layer Information
	SourceMAC          string // Source MAC address
	DestinationMAC     string // Destination MAC address
	LinkLayerProtocol   string // Protocol used in the link layer (e.g., Ethernet)

	// Network Layer Information
	SourceIP             string // Source IP address
	DestinationIP        string // Destination IP address
	NetworkLayerProtocol string // Protocol used in the network layer (e.g., IP)

	// Transport Layer Information
	SourcePort             int    // Source port number
	DestinationPort        int    // Destination port number
	TransportLayerProtocol string // Protocol used in the transport layer (TCP, UDP)

	// Application Layer Information
	ApplicationProtocol string // Protocol used in the application layer (HTTP, FTP, etc.)
	ProcessID           int32    // Process ID that generated the packet (for DPI)
	ProcessName         string // Name of the process
	ProcessDesc         string // Description of the process
	Payload             []byte // Payload data
	PayloadLength       int    // Size of the payload (if needed)
}

// Print displays the packet information in a clean format
func (p *Packet) Print() {
	fmt.Printf("Packet Information:\n")
	fmt.Printf("---------------------\n")
	fmt.Printf("Timestamp: %s\n", p.Timestamp)
	fmt.Printf("Packet Length: %d bytes\n", p.PacketLength)
	fmt.Printf("Direction: %s\n", p.Direction)
	fmt.Printf("Interface Name: %s\n", p.InterfaceName)
	fmt.Printf("Interface Description: %s\n", p.InterfaceDesc)

	fmt.Printf("\nLink Layer Information:\n")
	fmt.Printf("Source MAC: %s\n", p.SourceMAC)
	fmt.Printf("Destination MAC: %s\n", p.DestinationMAC)
	fmt.Printf("Link Layer Protocol: %s\n", p.LinkLayerProtocol)

	fmt.Printf("\nNetwork Layer Information:\n")
	fmt.Printf("Source IP: %s\n", p.SourceIP)
	fmt.Printf("Destination IP: %s\n", p.DestinationIP)
	fmt.Printf("Network Layer Protocol: %s\n", p.NetworkLayerProtocol)

	fmt.Printf("\nTransport Layer Information:\n")
	fmt.Printf("Source Port: %d\n", p.SourcePort)
	fmt.Printf("Destination Port: %d\n", p.DestinationPort)
	fmt.Printf("Transport Layer Protocol: %s\n", p.TransportLayerProtocol)

	fmt.Printf("\nApplication Layer Information:\n")
	fmt.Printf("Application Protocol: %s\n", p.ApplicationProtocol)
	fmt.Printf("Process ID: %d\n", p.ProcessID)
	fmt.Printf("Process Name: %s\n", p.ProcessName)
	fmt.Printf("Process Description: %s\n", p.ProcessDesc)
	fmt.Printf("Payload Length: %d bytes\n", p.PayloadLength)
}
