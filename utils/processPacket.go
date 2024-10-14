package utils

import (
	"firewall-windows-agent/types"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ProcessPacket processes a captured packet and returns a structured Packet object
func ProcessPacket(packet gopacket.Packet, device pcap.Interface , direction pcap.Direction) types.Packet {
    packetInfo := types.Packet{
        Timestamp:       time.Now().Format("03:04:05 PM 02-Jan-2006 Monday"),
        PacketLength:    len(packet.Data()),
        InterfaceName:   device.Name,
        InterfaceDesc:   device.Description,
    }
	// Check if the application layer is nil
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
    	packetInfo.Payload = appLayer.Payload()
    	packetInfo.PayloadLength = len(packetInfo.Payload)
	} else {
		packetInfo.Payload = nil
		packetInfo.PayloadLength = 0 // or some other default value
	}
    // Use helper functions to extract more information
    if direction == 1 {
        packetInfo.Direction = "Incoming";
    }else{
        packetInfo.Direction = "Outgoing";
    }
    packetInfo.SourceMAC, packetInfo.DestinationMAC, packetInfo.LinkLayerProtocol = getLinkLayerInfo(packet)
    packetInfo.SourceIP, packetInfo.DestinationIP, packetInfo.NetworkLayerProtocol = getNetworkLayerInfo(packet)
    packetInfo.SourcePort, packetInfo.DestinationPort, packetInfo.TransportLayerProtocol = getTransportLayerInfo(packet)
    packetInfo.ApplicationProtocol = getApplicationLayerInfo(packet)
	//packetInfo.ProcessID = GetProcessID(packetInfo.Direction,packetInfo.SourcePort,packetInfo.DestinationPort,packetInfo.TransportLayerProtocol)
    return packetInfo
}


// GetLinkLayerInfo extracts link layer information from the packet
func getLinkLayerInfo(packet gopacket.Packet) (string, string, string) {
    // Extract Ethernet layer
    ethLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethLayer != nil {
        ethernetPacket, _ := ethLayer.(*layers.Ethernet)

        sourceMAC := ethernetPacket.SrcMAC.String()
        destinationMAC := ethernetPacket.DstMAC.String()
        linkLayerProtocol := "Ethernet" // Link layer protocol

        return sourceMAC, destinationMAC, linkLayerProtocol
    }

    // Extract Wi-Fi (IEEE 802.11) layer
    wifiLayer := packet.Layer(layers.LayerTypeDot11)
    if wifiLayer != nil {
        wifiPacket, _ := wifiLayer.(*layers.Dot11)

        sourceMAC := wifiPacket.Address2.String() // Source MAC
        destinationMAC := wifiPacket.Address1.String() // Destination MAC
        linkLayerProtocol := "Wi-Fi" // Link layer protocol

        return sourceMAC, destinationMAC, linkLayerProtocol
    }

    // If no relevant link layer is found
    return "Unknown", "Unknown", "Unknown"
}

// GetNetworkLayerInfo extracts network layer information from the packet
func getNetworkLayerInfo(packet gopacket.Packet) (string, string, string) {
    // Extract IPv4 layer
    if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
        ipPacket, _ := ipLayer.(*layers.IPv4)
        sourceIP := ipPacket.SrcIP.String()
        destinationIP := ipPacket.DstIP.String()
        return sourceIP, destinationIP, "IPv4" // Network layer protocol
    }

    // Extract IPv6 layer
    if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
        ipv6Packet, _ := ipv6Layer.(*layers.IPv6)
        sourceIP := ipv6Packet.SrcIP.String()
        destinationIP := ipv6Packet.DstIP.String()
        return sourceIP, destinationIP, "IPv6" // Network layer protocol
    }

    // Extract ICMP layer
    if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
        // If it's an ICMP packet, we need the outer IP packet's source and destination
        if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
            ipPacket, _ := ipLayer.(*layers.IPv4)
            sourceIP := ipPacket.SrcIP.String()      // Source IP from outer IP header
            destinationIP := ipPacket.DstIP.String() // Destination IP from outer IP header
            return sourceIP, destinationIP, "ICMP"   // Network layer protocol
        }
    }

    // If no relevant network layer is found
    return "Unknown", "Unknown", "Unknown"
}

// GetTransportLayerInfo extracts transport layer information from the packet
func getTransportLayerInfo(packet gopacket.Packet) (int, int, string) {
    // Extract TCP layer
    if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
        tcpPacket, _ := tcpLayer.(*layers.TCP)
        return int(tcpPacket.SrcPort), int(tcpPacket.DstPort), "TCP" // Return ports and protocol
    }

    // Extract UDP layer
    if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
        udpPacket, _ := udpLayer.(*layers.UDP)
        return int(udpPacket.SrcPort), int(udpPacket.DstPort), "UDP" // Return ports and protocol
    }

    // If no relevant transport layer is found
    return -1, -1, "Unknown" // Return zero values for ports and empty protocol
}

// GetApplicationLayerInfo extracts application layer information from the packet
func getApplicationLayerInfo(_ gopacket.Packet) (string) {
    // Implement logic to extract Application Protocol
    return "#TODO DPI" // Placeholder return
}


