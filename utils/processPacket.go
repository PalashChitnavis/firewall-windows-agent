package utils

import (
	"firewall-windows-agent/types"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ProcessPacket processes a captured packet and returns a structured Packet object
func ProcessPacket(packet gopacket.Packet, device pcap.Interface) types.Packet {
    packetInfo := types.Packet{
        Timestamp:       time.Now().Format("03:04:05 PM 02-Jan-2006 Monday"),
        PacketLength:    len(packet.Data()),
        InterfaceName:   device.Name,
        InterfaceDesc:   device.Description,
		Payload: packet.ApplicationLayer().Payload(),
		PayloadLength: len(packet.ApplicationLayer().Payload()),
    }
    // Use helper functions to extract more information
    packetInfo.Direction = directionChecker(packet)
    packetInfo.SourceMAC, packetInfo.DestinationMAC, packetInfo.LinkLayerProtocol = getLinkLayerInfo(packet)
    packetInfo.SourceIP, packetInfo.DestinationIP, packetInfo.NetworkLayerProtocol = getNetworkLayerInfo(packet)
    packetInfo.SourcePort, packetInfo.DestinationPort, packetInfo.TransportLayerProtocol = getTransportLayerInfo(packet)
    packetInfo.ApplicationProtocol = getApplicationLayerInfo(packet)
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

    // Extract ARP layer
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arpPacket, _ := arpLayer.(*layers.ARP)

		// Convert byte arrays to net.IP
		sourceIP := net.IP(arpPacket.SourceProtAddress).String()  // Source IP from ARP packet
		destinationIP := net.IP(arpPacket.DstProtAddress).String() // Destination IP from ARP packet

		return sourceIP, destinationIP, "ARP" // Network layer protocol
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


// directionChecker checks if a packet is incoming, outgoing, or loopback
func directionChecker(packet gopacket.Packet) string {
    // Extract the IP layer (works for both IPv4 and IPv6)
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)
        // Get the local machine's IP addresses
        localIPs, err := getLocalIPs()
        if err != nil {
            log.Println("Error getting local IPs:", err)
            return "Error getting local IPs"
        }
     
        // Check for loopback (both source and destination are local IPs)
        if isLocalIP(ip.SrcIP, localIPs) && isLocalIP(ip.DstIP, localIPs) {
            return "Loopback"
        }

        // Check if packet is incoming (destination is local, source is not)
        if isLocalIP(ip.DstIP, localIPs) && !isLocalIP(ip.SrcIP, localIPs) {
            return "Incoming"
        }

        // Check if packet is outgoing (source is local, destination is not)
        if isLocalIP(ip.SrcIP, localIPs) && !isLocalIP(ip.DstIP, localIPs) {
            return "Outgoing"
        }
    }

    // If no IP layer is found or we can't determine direction
    return "Unknown"
}


// isLocalIP checks if an IP address matches one of the local machine's IPs
func isLocalIP(ip net.IP, localIPs []net.IP) bool {
    for _, localIP := range localIPs {
        if ip.Equal(localIP) {
            return true
        }
    }
    return false
}

// getLocalIPs retrieves all the local IP addresses of the machine
func getLocalIPs() ([]net.IP, error) {
    var ips []net.IP
    interfaces, err := net.Interfaces()
    if err != nil {
        return nil, err
    }

    for _, i := range interfaces {
        addrs, err := i.Addrs()
        if err != nil {
            return nil, err
        }
        for _, addr := range addrs {
            var ip net.IP
            switch v := addr.(type) {
            case *net.IPNet:
                ip = v.IP
            case *net.IPAddr:
                ip = v.IP
            }
            ips = append(ips, ip)
        }
    }
    return ips, nil
}
