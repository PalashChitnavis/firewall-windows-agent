package utils

import (
	"fmt"

	"github.com/shirou/gopsutil/net"
)

// GetProcessID finds the process ID for a given direction, ports, and transport protocol
func GetProcessID(direction string, sourcePort int, destPort int, transportProtocol string) int32 {
	if sourcePort < 0 && destPort < 0 {
		return -1
	}

	switch direction {
	case "Incoming":
		return findPIDFromPort(destPort, transportProtocol)
	case "Outgoing":
		return findPIDFromPort(sourcePort, transportProtocol)
	case "Loopback":
		return findPIDFromLoopback(sourcePort, destPort, transportProtocol)
	default:
		return -1
	}
}

// findPIDFromPort finds the PID for a given port and transport protocol
func findPIDFromPort(port int, transportProtocol string) int32 {
	connections, err := getConnectionsByProtocol(transportProtocol)
	if err != nil {
		return -1
	}

	// Iterate over connections and match the port
	for _, conn := range connections {
		// Check both local and remote ports for a match
		if int(conn.Laddr.Port) == port {
			return conn.Pid
		}
	}
	return -1
}

// findPIDFromLoopback handles loopback connections by checking both source and destination ports
func findPIDFromLoopback(sourcePort int, destPort int, transportProtocol string) int32 {
	connections, err := getConnectionsByProtocol(transportProtocol)
	if err != nil {
		return -1
	}

	// Loop through connections to find a match where both source and destination are local
	for _, conn := range connections {
		if isLoopback(conn.Laddr.IP) && isLoopback(conn.Raddr.IP) {
			if (int(conn.Laddr.Port) == sourcePort) ||
				(int(conn.Laddr.Port) == destPort) {
				return conn.Pid
			}
		}
	}
	return -1
}

// getConnectionsByProtocol retrieves network connections by protocol (TCP/UDP)
func getConnectionsByProtocol(protocol string) ([]net.ConnectionStat, error) {
	var conn []net.ConnectionStat
	var err error
	switch protocol {
	case "TCP":
		conn , err = net.Connections("tcp")
	case "UDP":
		conn , err = net.Connections("udp")
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
	//fmt.Println(conn)
	return conn,err
}

// isLoopback checks if an IP is a loopback address (127.0.0.1 or ::1)
func isLoopback(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1"
}
