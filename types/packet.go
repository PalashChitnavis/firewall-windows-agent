package types

type Packet struct {
	// Basic Information
	Timestamp       string // Time the packet was captured
	PacketLength          int       // Size of the packet
	Direction       string    // Direction (incoming, outgoing, loopback)
	InterfaceName   string    // Network interface used
	InterfaceDesc   string    // Description of the network interface

	// Link Layer Information
	SourceMAC      string // Source MAC address
	DestinationMAC string // Destination MAC address
	LinkLayerProtocol string // Protocol used in the link layer (e.g., Ethernet)

	// Network Layer Information
	SourceIP             string // Source IP address
	DestinationIP        string // Destination IP address
	NetworkLayerProtocol string // Protocol used in the network layer (e.g., IP)

	// Transport Layer Information
	SourcePort             int             // Source port number
	DestinationPort        int             // Destination port number
	TransportLayerProtocol string          // Protocol used in the transport layer (TCP, UDP)

	// Application Layer Information
	ApplicationProtocol string // Protocol used in the application layer (HTTP, FTP, etc.)
	ProcessID           int    // Process ID that generated the packet (for DPI)
	ProcessName         string // Name of the process
	ProcessDesc         string // Description of the process
	Payload             []byte // Payload data
	PayloadLength int // Size of the payload (if needed)
}
